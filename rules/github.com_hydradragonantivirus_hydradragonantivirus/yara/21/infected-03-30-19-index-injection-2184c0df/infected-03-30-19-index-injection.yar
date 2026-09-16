rule infected_03_30_19_index_injection {
  meta:
    description = "03-30-19 - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-03-30"
    hash1       = "b77081e5e47352abc53201528bede29991279353807673742f75a8406eeb7a3b"

  strings:
    $x1  = "';$bbb6b6b66=explode(\"1l\",\"tilps_gerp1ledocnelru1lemaner1lyarra_ni1lezilairesnu1lstegf1l5dm1lcexe_lruc1lofniphp1lstnetnoc_teg" ascii
    $s2  = "3459234735" ascii  
    $s3  = "3639556352" ascii  
    $s4  = "3639555328" ascii  
    $s5  = "2850357247" ascii  
    $s6  = "3639556963" ascii  
    $s7  = "3639553535" ascii  
    $s8  = "3459234728" ascii  
    $s9  = "3626237951" ascii  
    $s10 = "3639553536" ascii  
    $s11 = "3344430079" ascii  
    $s12 = "3639556864" ascii  
    $s13 = "3639552355" ascii  
    $s14 = "3639552352" ascii  
    $s15 = "3639555840" ascii  
    $s16 = "3522775360" ascii  
    $s17 = "3522775367" ascii  
    $s18 = "3639555071" ascii  
    $s19 = "x3c!DOCTYPE html>\\n\\x3chtml>\\n\\x3chead>\\n\\t\\x3cmeta charset=\\\"utf-8\\\">\\n\\t\\x3cmeta http-equiv=\\\"X-UA-Compatible" ascii
    $s20 = "1.0\\r\\nHost:\".$l14yYfXH[\"host\"].\"\\r\\nConnection:Close\\r\\n\\r\\n\");$l1lTyog='';while(!$GLOBALS[\"bbb6b6\"]($l14a)){$l1" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 100KB and
      (1 of ($x*) and 2 of them)
    ) or (all of them)
}