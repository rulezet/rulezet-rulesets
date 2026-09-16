rule TTP_XOR_WriteProcessMemory_cd16 {
  strings:
    $key_cd16 = { 9a 64 [2] a8 46 [2] ae 73 [2] 80 73 [2] bf 6f }

  condition:
    any of them
}