rule TTP_XOR_WriteProcessMemory_40c3 {
  strings:
    $key_40c3 = { 17 b1 [2] 25 93 [2] 23 a6 [2] 0d a6 [2] 32 ba }

  condition:
    any of them
}