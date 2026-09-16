rule TTP_XOR_WriteProcessMemory_4dd8 {
  strings:
    $key_4dd8 = { 1a aa [2] 28 88 [2] 2e bd [2] 00 bd [2] 3f a1 }

  condition:
    any of them
}