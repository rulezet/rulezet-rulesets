rule TTP_XOR_WriteProcessMemory_55d8 {
  strings:
    $key_55d8 = { 02 aa [2] 30 88 [2] 36 bd [2] 18 bd [2] 27 a1 }

  condition:
    any of them
}