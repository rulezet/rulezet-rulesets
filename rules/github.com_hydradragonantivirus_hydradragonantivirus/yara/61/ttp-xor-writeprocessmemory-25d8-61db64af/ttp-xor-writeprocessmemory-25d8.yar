rule TTP_XOR_WriteProcessMemory_25d8 {
  strings:
    $key_25d8 = { 72 aa [2] 40 88 [2] 46 bd [2] 68 bd [2] 57 a1 }

  condition:
    any of them
}