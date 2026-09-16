rule TTP_XOR_WriteProcessMemory_67d8 {
  strings:
    $key_67d8 = { 30 aa [2] 02 88 [2] 04 bd [2] 2a bd [2] 15 a1 }

  condition:
    any of them
}