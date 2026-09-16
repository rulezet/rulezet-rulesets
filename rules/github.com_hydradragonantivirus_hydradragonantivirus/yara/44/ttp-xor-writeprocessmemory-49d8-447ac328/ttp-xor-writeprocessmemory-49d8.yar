rule TTP_XOR_WriteProcessMemory_49d8 {
  strings:
    $key_49d8 = { 1e aa [2] 2c 88 [2] 2a bd [2] 04 bd [2] 3b a1 }

  condition:
    any of them
}