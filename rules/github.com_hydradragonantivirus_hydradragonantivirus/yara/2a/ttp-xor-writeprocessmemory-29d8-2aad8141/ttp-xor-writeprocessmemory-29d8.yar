rule TTP_XOR_WriteProcessMemory_29d8 {
  strings:
    $key_29d8 = { 7e aa [2] 4c 88 [2] 4a bd [2] 64 bd [2] 5b a1 }

  condition:
    any of them
}