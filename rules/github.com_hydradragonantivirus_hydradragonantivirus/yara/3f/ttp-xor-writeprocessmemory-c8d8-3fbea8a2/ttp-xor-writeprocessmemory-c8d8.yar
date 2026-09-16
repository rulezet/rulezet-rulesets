rule TTP_XOR_WriteProcessMemory_c8d8 {
  strings:
    $key_c8d8 = { 9f aa [2] ad 88 [2] ab bd [2] 85 bd [2] ba a1 }

  condition:
    any of them
}