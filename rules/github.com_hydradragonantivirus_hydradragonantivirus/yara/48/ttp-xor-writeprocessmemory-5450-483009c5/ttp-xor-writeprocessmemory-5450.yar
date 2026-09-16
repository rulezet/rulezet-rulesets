rule TTP_XOR_WriteProcessMemory_5450 {
  strings:
    $key_5450 = { 03 22 [2] 31 00 [2] 37 35 [2] 19 35 [2] 26 29 }

  condition:
    any of them
}