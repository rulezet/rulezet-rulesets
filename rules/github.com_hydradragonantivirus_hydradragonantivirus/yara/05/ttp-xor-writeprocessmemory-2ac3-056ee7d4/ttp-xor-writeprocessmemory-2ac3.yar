rule TTP_XOR_WriteProcessMemory_2ac3 {
  strings:
    $key_2ac3 = { 7d b1 [2] 4f 93 [2] 49 a6 [2] 67 a6 [2] 58 ba }

  condition:
    any of them
}