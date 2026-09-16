rule TTP_XOR_WriteProcessMemory_f370 {
  strings:
    $key_f370 = { a4 02 [2] 96 20 [2] 90 15 [2] be 15 [2] 81 09 }

  condition:
    any of them
}