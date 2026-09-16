rule TTP_XOR_WriteProcessMemory_1055 {
  strings:
    $key_1055 = { 47 27 [2] 75 05 [2] 73 30 [2] 5d 30 [2] 62 2c }

  condition:
    any of them
}