rule TTP_XOR_WriteProcessMemory_2dd8 {
  strings:
    $key_2dd8 = { 7a aa [2] 48 88 [2] 4e bd [2] 60 bd [2] 5f a1 }

  condition:
    any of them
}