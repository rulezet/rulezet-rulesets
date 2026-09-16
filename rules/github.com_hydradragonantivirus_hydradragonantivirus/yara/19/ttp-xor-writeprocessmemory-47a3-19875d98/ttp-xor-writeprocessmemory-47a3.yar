rule TTP_XOR_WriteProcessMemory_47a3 {
  strings:
    $key_47a3 = { 10 d1 [2] 22 f3 [2] 24 c6 [2] 0a c6 [2] 35 da }

  condition:
    any of them
}