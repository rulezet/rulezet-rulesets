rule TTP_XOR_WriteProcessMemory_6684 {
  strings:
    $key_6684 = { 31 f6 [2] 03 d4 [2] 05 e1 [2] 2b e1 [2] 14 fd }

  condition:
    any of them
}