rule TTP_XOR_WriteProcessMemory_f3a3 {
  strings:
    $key_f3a3 = { a4 d1 [2] 96 f3 [2] 90 c6 [2] be c6 [2] 81 da }

  condition:
    any of them
}