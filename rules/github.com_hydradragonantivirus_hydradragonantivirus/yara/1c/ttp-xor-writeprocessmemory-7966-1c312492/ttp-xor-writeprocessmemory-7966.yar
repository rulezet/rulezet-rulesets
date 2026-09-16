rule TTP_XOR_WriteProcessMemory_7966 {
  strings:
    $key_7966 = { 2e 14 [2] 1c 36 [2] 1a 03 [2] 34 03 [2] 0b 1f }

  condition:
    any of them
}