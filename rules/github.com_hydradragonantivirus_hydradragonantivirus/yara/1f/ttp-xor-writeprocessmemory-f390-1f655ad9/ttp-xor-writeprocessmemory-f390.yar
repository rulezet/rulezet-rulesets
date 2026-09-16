rule TTP_XOR_WriteProcessMemory_f390 {
  strings:
    $key_f390 = { a4 e2 [2] 96 c0 [2] 90 f5 [2] be f5 [2] 81 e9 }

  condition:
    any of them
}