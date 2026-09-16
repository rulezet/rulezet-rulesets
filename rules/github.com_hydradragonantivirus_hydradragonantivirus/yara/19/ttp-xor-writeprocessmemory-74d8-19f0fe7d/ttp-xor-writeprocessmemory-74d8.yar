rule TTP_XOR_WriteProcessMemory_74d8 {
  strings:
    $key_74d8 = { 23 aa [2] 11 88 [2] 17 bd [2] 39 bd [2] 06 a1 }

  condition:
    any of them
}