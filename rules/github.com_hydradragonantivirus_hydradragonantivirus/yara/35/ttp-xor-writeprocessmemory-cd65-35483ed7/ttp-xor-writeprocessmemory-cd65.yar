rule TTP_XOR_WriteProcessMemory_cd65 {
  strings:
    $key_cd65 = { 9a 17 [2] a8 35 [2] ae 00 [2] 80 00 [2] bf 1c }

  condition:
    any of them
}