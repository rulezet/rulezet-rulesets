rule TTP_XOR_WriteProcessMemory_29d5 {
  strings:
    $key_29d5 = { 7e a7 [2] 4c 85 [2] 4a b0 [2] 64 b0 [2] 5b ac }

  condition:
    any of them
}