rule TTP_XOR_WriteProcessMemory_0bd8 {
  strings:
    $key_0bd8 = { 5c aa [2] 6e 88 [2] 68 bd [2] 46 bd [2] 79 a1 }

  condition:
    any of them
}