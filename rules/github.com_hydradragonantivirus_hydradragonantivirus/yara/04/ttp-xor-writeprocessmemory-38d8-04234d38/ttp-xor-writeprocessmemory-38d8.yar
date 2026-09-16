rule TTP_XOR_WriteProcessMemory_38d8 {
  strings:
    $key_38d8 = { 6f aa [2] 5d 88 [2] 5b bd [2] 75 bd [2] 4a a1 }

  condition:
    any of them
}