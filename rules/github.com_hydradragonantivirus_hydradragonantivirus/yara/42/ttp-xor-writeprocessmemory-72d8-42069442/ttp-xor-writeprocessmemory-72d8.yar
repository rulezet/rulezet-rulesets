rule TTP_XOR_WriteProcessMemory_72d8 {
  strings:
    $key_72d8 = { 25 aa [2] 17 88 [2] 11 bd [2] 3f bd [2] 00 a1 }

  condition:
    any of them
}