rule TTP_XOR_WriteProcessMemory_74c3 {
  strings:
    $key_74c3 = { 23 b1 [2] 11 93 [2] 17 a6 [2] 39 a6 [2] 06 ba }

  condition:
    any of them
}