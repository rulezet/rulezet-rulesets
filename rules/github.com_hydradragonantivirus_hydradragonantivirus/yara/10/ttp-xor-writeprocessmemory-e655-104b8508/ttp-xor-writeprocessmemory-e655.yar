rule TTP_XOR_WriteProcessMemory_e655 {
  strings:
    $key_e655 = { b1 27 [2] 83 05 [2] 85 30 [2] ab 30 [2] 94 2c }

  condition:
    any of them
}