rule TTP_XOR_WriteProcessMemory_0bd4 {
  strings:
    $key_0bd4 = { 5c a6 [2] 6e 84 [2] 68 b1 [2] 46 b1 [2] 79 ad }

  condition:
    any of them
}