rule TTP_XOR_WriteProcessMemory_5bd8 {
  strings:
    $key_5bd8 = { 0c aa [2] 3e 88 [2] 38 bd [2] 16 bd [2] 29 a1 }

  condition:
    any of them
}