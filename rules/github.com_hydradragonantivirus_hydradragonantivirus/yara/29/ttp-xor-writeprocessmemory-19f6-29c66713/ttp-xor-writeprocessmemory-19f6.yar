rule TTP_XOR_WriteProcessMemory_19f6 {
  strings:
    $key_19f6 = { 4e 84 [2] 7c a6 [2] 7a 93 [2] 54 93 [2] 6b 8f }

  condition:
    any of them
}