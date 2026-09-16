rule TTP_XOR_WriteProcessMemory_3055 {
  strings:
    $key_3055 = { 67 27 [2] 55 05 [2] 53 30 [2] 7d 30 [2] 42 2c }

  condition:
    any of them
}