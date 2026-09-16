rule TTP_XOR_WriteProcessMemory_5ac3 {
  strings:
    $key_5ac3 = { 0d b1 [2] 3f 93 [2] 39 a6 [2] 17 a6 [2] 28 ba }

  condition:
    any of them
}