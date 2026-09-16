rule TTP_XOR_WriteProcessMemory_5cf6 {
  strings:
    $key_5cf6 = { 0b 84 [2] 39 a6 [2] 3f 93 [2] 11 93 [2] 2e 8f }

  condition:
    any of them
}