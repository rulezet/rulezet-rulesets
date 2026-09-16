rule TTP_XOR_WriteProcessMemory_4ac3 {
  strings:
    $key_4ac3 = { 1d b1 [2] 2f 93 [2] 29 a6 [2] 07 a6 [2] 38 ba }

  condition:
    any of them
}