rule TTP_XOR_WriteProcessMemory_46c3 {
  strings:
    $key_46c3 = { 11 b1 [2] 23 93 [2] 25 a6 [2] 0b a6 [2] 34 ba }

  condition:
    any of them
}