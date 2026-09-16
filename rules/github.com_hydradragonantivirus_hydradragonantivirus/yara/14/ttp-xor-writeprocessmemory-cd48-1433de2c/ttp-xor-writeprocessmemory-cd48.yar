rule TTP_XOR_WriteProcessMemory_cd48 {
  strings:
    $key_cd48 = { 9a 3a [2] a8 18 [2] ae 2d [2] 80 2d [2] bf 31 }

  condition:
    any of them
}