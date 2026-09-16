rule TTP_XOR_WriteProcessMemory_1ac3 {
  strings:
    $key_1ac3 = { 4d b1 [2] 7f 93 [2] 79 a6 [2] 57 a6 [2] 68 ba }

  condition:
    any of them
}