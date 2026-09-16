rule TTP_XOR_WriteProcessMemory_23d8 {
  strings:
    $key_23d8 = { 74 aa [2] 46 88 [2] 40 bd [2] 6e bd [2] 51 a1 }

  condition:
    any of them
}