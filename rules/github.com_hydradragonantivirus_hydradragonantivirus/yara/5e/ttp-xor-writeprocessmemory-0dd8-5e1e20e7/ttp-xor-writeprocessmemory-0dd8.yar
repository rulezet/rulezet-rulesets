rule TTP_XOR_WriteProcessMemory_0dd8 {
  strings:
    $key_0dd8 = { 5a aa [2] 68 88 [2] 6e bd [2] 40 bd [2] 7f a1 }

  condition:
    any of them
}