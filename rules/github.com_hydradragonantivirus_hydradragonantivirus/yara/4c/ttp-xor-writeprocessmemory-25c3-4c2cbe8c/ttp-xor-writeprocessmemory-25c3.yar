rule TTP_XOR_WriteProcessMemory_25c3 {
  strings:
    $key_25c3 = { 72 b1 [2] 40 93 [2] 46 a6 [2] 68 a6 [2] 57 ba }

  condition:
    any of them
}