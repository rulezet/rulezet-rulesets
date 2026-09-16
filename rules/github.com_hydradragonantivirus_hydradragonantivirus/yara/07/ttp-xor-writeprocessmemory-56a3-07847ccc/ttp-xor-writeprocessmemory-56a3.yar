rule TTP_XOR_WriteProcessMemory_56a3 {
  strings:
    $key_56a3 = { 01 d1 [2] 33 f3 [2] 35 c6 [2] 1b c6 [2] 24 da }

  condition:
    any of them
}