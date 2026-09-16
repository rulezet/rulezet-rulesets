rule TTP_XOR_WriteProcessMemory_f310 {
  strings:
    $key_f310 = { a4 62 [2] 96 40 [2] 90 75 [2] be 75 [2] 81 69 }

  condition:
    any of them
}