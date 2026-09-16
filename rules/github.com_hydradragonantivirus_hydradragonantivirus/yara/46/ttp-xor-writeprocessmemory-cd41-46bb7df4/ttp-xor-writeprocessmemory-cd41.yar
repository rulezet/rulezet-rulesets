rule TTP_XOR_WriteProcessMemory_cd41 {
  strings:
    $key_cd41 = { 9a 33 [2] a8 11 [2] ae 24 [2] 80 24 [2] bf 38 }

  condition:
    any of them
}