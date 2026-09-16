rule TTP_XOR_WriteProcessMemory_79d5 {
  strings:
    $key_79d5 = { 2e a7 [2] 1c 85 [2] 1a b0 [2] 34 b0 [2] 0b ac }

  condition:
    any of them
}