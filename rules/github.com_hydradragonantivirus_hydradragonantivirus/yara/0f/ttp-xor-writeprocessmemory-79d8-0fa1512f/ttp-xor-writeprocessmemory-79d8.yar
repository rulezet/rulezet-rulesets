rule TTP_XOR_WriteProcessMemory_79d8 {
  strings:
    $key_79d8 = { 2e aa [2] 1c 88 [2] 1a bd [2] 34 bd [2] 0b a1 }

  condition:
    any of them
}