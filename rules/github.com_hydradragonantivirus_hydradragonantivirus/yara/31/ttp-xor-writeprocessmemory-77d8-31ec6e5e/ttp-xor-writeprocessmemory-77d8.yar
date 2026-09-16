rule TTP_XOR_WriteProcessMemory_77d8 {
  strings:
    $key_77d8 = { 20 aa [2] 12 88 [2] 14 bd [2] 3a bd [2] 05 a1 }

  condition:
    any of them
}