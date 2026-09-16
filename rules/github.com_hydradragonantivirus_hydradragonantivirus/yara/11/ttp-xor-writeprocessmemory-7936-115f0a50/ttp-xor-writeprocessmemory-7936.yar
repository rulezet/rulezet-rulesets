rule TTP_XOR_WriteProcessMemory_7936 {
  strings:
    $key_7936 = { 2e 44 [2] 1c 66 [2] 1a 53 [2] 34 53 [2] 0b 4f }

  condition:
    any of them
}