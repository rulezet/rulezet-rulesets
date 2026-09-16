rule TTP_XOR_WriteProcessMemory_f350 {
  strings:
    $key_f350 = { a4 22 [2] 96 00 [2] 90 35 [2] be 35 [2] 81 29 }

  condition:
    any of them
}