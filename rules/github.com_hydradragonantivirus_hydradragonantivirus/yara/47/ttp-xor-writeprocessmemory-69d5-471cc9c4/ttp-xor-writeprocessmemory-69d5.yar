rule TTP_XOR_WriteProcessMemory_69d5 {
  strings:
    $key_69d5 = { 3e a7 [2] 0c 85 [2] 0a b0 [2] 24 b0 [2] 1b ac }

  condition:
    any of them
}