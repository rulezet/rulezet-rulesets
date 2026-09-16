rule TTP_XOR_WriteProcessMemory_59d5 {
  strings:
    $key_59d5 = { 0e a7 [2] 3c 85 [2] 3a b0 [2] 14 b0 [2] 2b ac }

  condition:
    any of them
}