rule TTP_XOR_WriteProcessMemory_49d5 {
  strings:
    $key_49d5 = { 1e a7 [2] 2c 85 [2] 2a b0 [2] 04 b0 [2] 3b ac }

  condition:
    any of them
}