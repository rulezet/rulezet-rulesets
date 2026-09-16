rule TTP_XOR_WriteProcessMemory_73d8 {
  strings:
    $key_73d8 = { 24 aa [2] 16 88 [2] 10 bd [2] 3e bd [2] 01 a1 }

  condition:
    any of them
}