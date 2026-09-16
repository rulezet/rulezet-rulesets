rule TTP_XOR_WriteProcessMemory_dbd2 {
  strings:
    $key_dbd2 = { 8c a0 [2] be 82 [2] b8 b7 [2] 96 b7 [2] a9 ab }

  condition:
    any of them
}