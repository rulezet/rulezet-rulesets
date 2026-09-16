rule TTP_XOR_WriteProcessMemory_15d8 {
  strings:
    $key_15d8 = { 42 aa [2] 70 88 [2] 76 bd [2] 58 bd [2] 67 a1 }

  condition:
    any of them
}