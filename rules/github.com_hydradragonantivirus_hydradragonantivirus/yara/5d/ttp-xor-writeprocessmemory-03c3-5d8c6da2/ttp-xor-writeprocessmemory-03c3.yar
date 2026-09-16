rule TTP_XOR_WriteProcessMemory_03c3 {
  strings:
    $key_03c3 = { 54 b1 [2] 66 93 [2] 60 a6 [2] 4e a6 [2] 71 ba }

  condition:
    any of them
}