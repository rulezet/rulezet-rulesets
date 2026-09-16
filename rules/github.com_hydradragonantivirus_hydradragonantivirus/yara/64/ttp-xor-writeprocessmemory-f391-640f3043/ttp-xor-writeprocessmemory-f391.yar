rule TTP_XOR_WriteProcessMemory_f391 {
  strings:
    $key_f391 = { a4 e3 [2] 96 c1 [2] 90 f4 [2] be f4 [2] 81 e8 }

  condition:
    any of them
}