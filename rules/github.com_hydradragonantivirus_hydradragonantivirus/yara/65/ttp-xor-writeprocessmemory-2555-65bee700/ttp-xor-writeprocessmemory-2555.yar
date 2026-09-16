rule TTP_XOR_WriteProcessMemory_2555 {
  strings:
    $key_2555 = { 72 27 [2] 40 05 [2] 46 30 [2] 68 30 [2] 57 2c }

  condition:
    any of them
}