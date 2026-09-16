rule infected_05_29_18_pythonsymlinker_sym {
  meta:
    description = "pythonsymlinker - file sym.py"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-29"
    hash1       = "72e092cd8922e74b903de63357b81a49e65c4051aa15bed504b6053525987686"

  strings:
            $s4  = "ln -s" fullword ascii
        $s6  = "open('/etc/passwd','r')" fullword ascii
    $s7  = "get=_blank"
    $s15 = "counter,fusr,fusr,path,fsite" fullword ascii
    $s8  = "ips.write" fullword ascii
    $s9  = "xusr=xusr.replace('/home/','')" ascii
    $s10 = "xxsite=xxsite.replace(\".db\",\"\")" fullword ascii
    $s11 = "ips=open"
    $s12 = "os.system" fullword ascii
    $s13 = "hta ="
    $s16 = ".htaccess" fullword ascii
    $s14 = "path=os.getcwd()" fullword ascii

  condition:
    (uint16(0) == 0x2020 and
      filesize < 5KB and
      (8 of them)
    ) or (all of them)
}