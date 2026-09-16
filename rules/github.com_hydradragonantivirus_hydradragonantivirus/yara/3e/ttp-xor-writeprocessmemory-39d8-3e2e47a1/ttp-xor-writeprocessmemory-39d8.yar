rule TTP_XOR_WriteProcessMemory_39d8 {
  strings:
    $key_39d8 = { 6e aa [2] 5c 88 [2] 5a bd [2] 74 bd [2] 4b a1 }

  condition:
    any of them
}