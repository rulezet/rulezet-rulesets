rule TTP_XOR_WriteProcessMemory_0fe2 {
  strings:
    $key_0fe2 = { 58 90 [2] 6a b2 [2] 6c 87 [2] 42 87 [2] 7d 9b }

  condition:
    any of them
}