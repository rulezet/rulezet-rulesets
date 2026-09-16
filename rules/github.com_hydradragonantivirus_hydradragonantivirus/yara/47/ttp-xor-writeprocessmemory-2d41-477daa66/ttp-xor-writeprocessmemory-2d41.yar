rule TTP_XOR_WriteProcessMemory_2d41 {
  strings:
    $key_2d41 = { 7a 33 [2] 48 11 [2] 4e 24 [2] 60 24 [2] 5f 38 }

  condition:
    any of them
}