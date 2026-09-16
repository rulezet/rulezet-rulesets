rule TTP_XOR_WriteProcessMemory_f3c1 {
  strings:
    $key_f3c1 = { a4 b3 [2] 96 91 [2] 90 a4 [2] be a4 [2] 81 b8 }

  condition:
    any of them
}