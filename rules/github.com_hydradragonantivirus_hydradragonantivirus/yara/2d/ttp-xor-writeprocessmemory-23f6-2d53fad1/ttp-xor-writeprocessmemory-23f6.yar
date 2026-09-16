rule TTP_XOR_WriteProcessMemory_23f6 {
  strings:
    $key_23f6 = { 74 84 [2] 46 a6 [2] 40 93 [2] 6e 93 [2] 51 8f }

  condition:
    any of them
}