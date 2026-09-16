rule TTP_XOR_WriteProcessMemory_dbd4 {
  strings:
    $key_dbd4 = { 8c a6 [2] be 84 [2] b8 b1 [2] 96 b1 [2] a9 ad }

  condition:
    any of them
}