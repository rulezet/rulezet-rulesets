rule TTP_XOR_WriteProcessMemory_f352 {
  strings:
    $key_f352 = { a4 20 [2] 96 02 [2] 90 37 [2] be 37 [2] 81 2b }

  condition:
    any of them
}