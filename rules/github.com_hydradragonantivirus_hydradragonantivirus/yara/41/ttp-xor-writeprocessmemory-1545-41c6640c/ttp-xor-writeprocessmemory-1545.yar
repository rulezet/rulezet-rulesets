rule TTP_XOR_WriteProcessMemory_1545 {
  strings:
    $key_1545 = { 42 37 [2] 70 15 [2] 76 20 [2] 58 20 [2] 67 3c }

  condition:
    any of them
}