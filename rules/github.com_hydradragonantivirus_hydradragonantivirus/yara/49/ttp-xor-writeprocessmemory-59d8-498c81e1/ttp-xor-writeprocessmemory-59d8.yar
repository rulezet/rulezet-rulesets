rule TTP_XOR_WriteProcessMemory_59d8 {
  strings:
    $key_59d8 = { 0e aa [2] 3c 88 [2] 3a bd [2] 14 bd [2] 2b a1 }

  condition:
    any of them
}