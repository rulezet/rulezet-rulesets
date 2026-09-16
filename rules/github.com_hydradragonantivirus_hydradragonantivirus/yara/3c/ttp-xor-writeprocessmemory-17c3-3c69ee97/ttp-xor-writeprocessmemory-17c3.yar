rule TTP_XOR_WriteProcessMemory_17c3 {
  strings:
    $key_17c3 = { 40 b1 [2] 72 93 [2] 74 a6 [2] 5a a6 [2] 65 ba }

  condition:
    any of them
}