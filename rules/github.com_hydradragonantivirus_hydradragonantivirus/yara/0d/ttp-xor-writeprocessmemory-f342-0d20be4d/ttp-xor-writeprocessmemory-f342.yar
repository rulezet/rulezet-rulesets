rule TTP_XOR_WriteProcessMemory_f342 {
  strings:
    $key_f342 = { a4 30 [2] 96 12 [2] 90 27 [2] be 27 [2] 81 3b }

  condition:
    any of them
}