rule TTP_XOR_WriteProcessMemory_f341 {
  strings:
    $key_f341 = { a4 33 [2] 96 11 [2] 90 24 [2] be 24 [2] 81 38 }

  condition:
    any of them
}