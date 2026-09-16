rule TTP_XOR_WriteProcessMemory_c853 {
  strings:
    $key_c853 = { 9f 21 [2] ad 03 [2] ab 36 [2] 85 36 [2] ba 2a }

  condition:
    any of them
}