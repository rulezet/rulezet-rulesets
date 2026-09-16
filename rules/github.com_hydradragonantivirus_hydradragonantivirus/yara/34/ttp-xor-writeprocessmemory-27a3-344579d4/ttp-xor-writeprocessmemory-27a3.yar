rule TTP_XOR_WriteProcessMemory_27a3 {
  strings:
    $key_27a3 = { 70 d1 [2] 42 f3 [2] 44 c6 [2] 6a c6 [2] 55 da }

  condition:
    any of them
}