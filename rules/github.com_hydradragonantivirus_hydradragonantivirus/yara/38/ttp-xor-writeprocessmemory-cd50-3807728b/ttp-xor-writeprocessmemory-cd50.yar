rule TTP_XOR_WriteProcessMemory_cd50 {
  strings:
    $key_cd50 = { 9a 22 [2] a8 00 [2] ae 35 [2] 80 35 [2] bf 29 }

  condition:
    any of them
}