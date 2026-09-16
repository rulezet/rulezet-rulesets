rule TTP_XOR_WriteProcessMemory_4555 {
  strings:
    $key_4555 = { 12 27 [2] 20 05 [2] 26 30 [2] 08 30 [2] 37 2c }

  condition:
    any of them
}