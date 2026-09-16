rule capa_os_strings: WEBSHELL PROD {
  meta:
    description = "typical webshell OS commands"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/14"

  strings:
        $w1        = "net localgroup administrators" nocase wide ascii
    $w2        = "net user" nocase wide ascii
    $w3        = "/add" nocase wide ascii
        $l1        = "/etc/shadow" wide ascii
    $l2        = "/etc/ssh/sshd_config" wide ascii
    $take_two1 = "net user" nocase wide ascii
    $take_two2 = "/add" nocase wide ascii

  condition:
    filesize < 300KB and
    not uint16(0) == 0x5a4d and (
      all of ($w*) or
      all of ($l*) or
      2 of ($take_two*)
    )
}