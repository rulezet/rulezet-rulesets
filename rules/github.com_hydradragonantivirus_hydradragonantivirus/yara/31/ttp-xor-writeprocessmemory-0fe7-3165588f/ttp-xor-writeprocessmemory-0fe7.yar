rule TTP_XOR_WriteProcessMemory_0fe7 {
  strings:
    $key_0fe7 = { 58 95 [2] 6a b7 [2] 6c 82 [2] 42 82 [2] 7d 9e }

  condition:
    any of them
}