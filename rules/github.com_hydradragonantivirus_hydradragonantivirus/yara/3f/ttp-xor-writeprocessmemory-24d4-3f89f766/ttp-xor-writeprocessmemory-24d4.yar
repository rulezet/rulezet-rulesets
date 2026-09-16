rule TTP_XOR_WriteProcessMemory_24d4 {
  strings:
    $key_24d4 = { 73 a6 [2] 41 84 [2] 47 b1 [2] 69 b1 [2] 56 ad }

  condition:
    any of them
}