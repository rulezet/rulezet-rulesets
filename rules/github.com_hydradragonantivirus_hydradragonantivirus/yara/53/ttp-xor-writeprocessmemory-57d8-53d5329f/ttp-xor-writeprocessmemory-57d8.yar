rule TTP_XOR_WriteProcessMemory_57d8 {
  strings:
    $key_57d8 = { 00 aa [2] 32 88 [2] 34 bd [2] 1a bd [2] 25 a1 }

  condition:
    any of them
}