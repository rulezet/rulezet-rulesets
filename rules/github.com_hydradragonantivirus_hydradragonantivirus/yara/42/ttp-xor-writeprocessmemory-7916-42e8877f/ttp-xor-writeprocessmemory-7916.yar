rule TTP_XOR_WriteProcessMemory_7916 {
  strings:
    $key_7916 = { 2e 64 [2] 1c 46 [2] 1a 73 [2] 34 73 [2] 0b 6f }

  condition:
    any of them
}