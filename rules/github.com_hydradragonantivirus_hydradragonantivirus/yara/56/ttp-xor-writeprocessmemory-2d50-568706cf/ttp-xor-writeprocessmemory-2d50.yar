rule TTP_XOR_WriteProcessMemory_2d50 {
  strings:
    $key_2d50 = { 7a 22 [2] 48 00 [2] 4e 35 [2] 60 35 [2] 5f 29 }

  condition:
    any of them
}