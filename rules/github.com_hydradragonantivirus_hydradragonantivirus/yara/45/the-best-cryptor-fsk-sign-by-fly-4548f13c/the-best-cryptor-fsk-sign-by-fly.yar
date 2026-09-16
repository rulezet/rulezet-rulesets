import "pe"
rule The_Best_Cryptor____FsK_____Sign_By_fly {
  strings:
    $a0 = { EB 06 56 52 55 4C 5A 00 90 90 90 90 90 90 90 90 }

  condition:
    $a0 at pe.entry_point
}