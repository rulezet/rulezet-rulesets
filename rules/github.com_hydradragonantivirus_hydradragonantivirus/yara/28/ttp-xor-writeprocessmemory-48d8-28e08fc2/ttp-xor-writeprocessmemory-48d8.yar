rule TTP_XOR_WriteProcessMemory_48d8 {
  strings:
    $key_48d8 = { 1f aa [2] 2d 88 [2] 2b bd [2] 05 bd [2] 3a a1 }

  condition:
    any of them
}