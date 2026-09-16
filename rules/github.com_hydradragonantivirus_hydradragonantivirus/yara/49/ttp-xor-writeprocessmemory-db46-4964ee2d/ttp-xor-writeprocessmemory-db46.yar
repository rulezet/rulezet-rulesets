rule TTP_XOR_WriteProcessMemory_db46 {
  strings:
    $key_db46 = { 8c 34 [2] be 16 [2] b8 23 [2] 96 23 [2] a9 3f }

  condition:
    any of them
}