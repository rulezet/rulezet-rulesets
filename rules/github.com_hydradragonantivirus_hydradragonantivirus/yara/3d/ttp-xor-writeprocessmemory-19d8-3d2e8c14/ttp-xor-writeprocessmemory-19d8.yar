rule TTP_XOR_WriteProcessMemory_19d8 {
  strings:
    $key_19d8 = { 4e aa [2] 7c 88 [2] 7a bd [2] 54 bd [2] 6b a1 }

  condition:
    any of them
}