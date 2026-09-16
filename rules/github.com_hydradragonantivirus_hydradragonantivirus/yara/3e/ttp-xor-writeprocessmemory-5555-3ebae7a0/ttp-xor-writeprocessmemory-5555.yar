rule TTP_XOR_WriteProcessMemory_5555 {
  strings:
    $key_5555 = { 02 27 [2] 30 05 [2] 36 30 [2] 18 30 [2] 27 2c }

  condition:
    any of them
}