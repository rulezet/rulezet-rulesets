rule TTP_XOR_WriteProcessMemory_50d8 {
  strings:
    $key_50d8 = { 07 aa [2] 35 88 [2] 33 bd [2] 1d bd [2] 22 a1 }

  condition:
    any of them
}