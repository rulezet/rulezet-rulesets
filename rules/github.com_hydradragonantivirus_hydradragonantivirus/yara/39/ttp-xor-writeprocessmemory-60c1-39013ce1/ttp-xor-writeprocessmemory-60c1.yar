rule TTP_XOR_WriteProcessMemory_60c1 {
  strings:
    $key_60c1 = { 37 b3 [2] 05 91 [2] 03 a4 [2] 2d a4 [2] 12 b8 }

  condition:
    any of them
}