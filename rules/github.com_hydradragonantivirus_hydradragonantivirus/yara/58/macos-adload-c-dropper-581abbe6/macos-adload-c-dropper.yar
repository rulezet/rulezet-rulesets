rule macos_adload_c_dropper: adware {
  meta:
    description = "MACOS.ADLOAD"

  strings:
    $shebang  = "#!"
    $string_1 = "mktemp -d /tmp"
    $string_2 = "head -n 1 | rev)"
    $string_3 = "U2FsdGVkX1"
    $string_4 = "-256-cbc"
    $string_5 = "killall Terminal "

  condition:
    $shebang at 0 and all of ($string_*)
}