rule TTP_XOR_WriteProcessMemory_64d8 {
  strings:
    $key_64d8 = { 33 aa [2] 01 88 [2] 07 bd [2] 29 bd [2] 16 a1 }

  condition:
    any of them
}