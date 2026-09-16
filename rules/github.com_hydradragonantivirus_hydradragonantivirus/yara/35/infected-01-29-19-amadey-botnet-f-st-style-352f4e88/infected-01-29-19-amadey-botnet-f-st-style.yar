rule infected_01_29_19_amadey_botnet_f_st_style {
  meta:
    description = "amadey-botnet - file style.css"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-01-30"
    hash1       = "d38b01f2bc4f51954426964e89e540d5bc2ad91a0206451021e10db1ce02deb4"

  strings:
    $s1 = ": #242424;" fullword ascii  
    $s2 = ": #3E3E3E;" fullword ascii  

  condition:
    (uint16(0) == 0x6f62 and
      filesize < 3KB and
      (all of them)
    ) or (all of them)
}