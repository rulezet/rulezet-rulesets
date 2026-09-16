rule TTP_XOR_WriteProcessMemory_1355 {
  strings:
    $key_1355 = { 44 27 [2] 76 05 [2] 70 30 [2] 5e 30 [2] 61 2c }

  condition:
    any of them
}