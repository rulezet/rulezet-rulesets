rule TTP_XOR_WriteProcessMemory_5dd8 {
  strings:
    $key_5dd8 = { 0a aa [2] 38 88 [2] 3e bd [2] 10 bd [2] 2f a1 }

  condition:
    any of them
}