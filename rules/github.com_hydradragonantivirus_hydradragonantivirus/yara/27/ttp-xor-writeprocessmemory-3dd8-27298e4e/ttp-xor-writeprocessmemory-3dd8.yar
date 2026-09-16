rule TTP_XOR_WriteProcessMemory_3dd8 {
  strings:
    $key_3dd8 = { 6a aa [2] 58 88 [2] 5e bd [2] 70 bd [2] 4f a1 }

  condition:
    any of them
}