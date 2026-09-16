rule TTP_XOR_WriteProcessMemory_60c3 {
  strings:
    $key_60c3 = { 37 b1 [2] 05 93 [2] 03 a6 [2] 2d a6 [2] 12 ba }

  condition:
    any of them
}