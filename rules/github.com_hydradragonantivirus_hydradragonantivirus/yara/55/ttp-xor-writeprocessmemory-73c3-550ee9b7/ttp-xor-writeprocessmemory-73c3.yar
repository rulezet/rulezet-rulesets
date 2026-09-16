rule TTP_XOR_WriteProcessMemory_73c3 {
  strings:
    $key_73c3 = { 24 b1 [2] 16 93 [2] 10 a6 [2] 3e a6 [2] 01 ba }

  condition:
    any of them
}