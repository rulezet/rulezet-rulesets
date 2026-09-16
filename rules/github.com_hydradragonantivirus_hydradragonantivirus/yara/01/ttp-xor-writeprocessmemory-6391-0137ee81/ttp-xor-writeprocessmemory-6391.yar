rule TTP_XOR_WriteProcessMemory_6391 {
  strings:
    $key_6391 = { 34 e3 [2] 06 c1 [2] 00 f4 [2] 2e f4 [2] 11 e8 }

  condition:
    any of them
}