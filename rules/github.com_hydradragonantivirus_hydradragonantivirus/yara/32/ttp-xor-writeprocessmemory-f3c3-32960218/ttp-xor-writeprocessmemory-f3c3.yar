rule TTP_XOR_WriteProcessMemory_f3c3 {
  strings:
    $key_f3c3 = { a4 b1 [2] 96 93 [2] 90 a6 [2] be a6 [2] 81 ba }

  condition:
    any of them
}