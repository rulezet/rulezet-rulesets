rule TTP_XOR_WriteProcessMemory_54c3 {
  strings:
    $key_54c3 = { 03 b1 [2] 31 93 [2] 37 a6 [2] 19 a6 [2] 26 ba }

  condition:
    any of them
}