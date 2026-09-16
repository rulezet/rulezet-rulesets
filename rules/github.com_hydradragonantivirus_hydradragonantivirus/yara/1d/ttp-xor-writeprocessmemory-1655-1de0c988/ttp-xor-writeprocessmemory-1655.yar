rule TTP_XOR_WriteProcessMemory_1655 {
  strings:
    $key_1655 = { 41 27 [2] 73 05 [2] 75 30 [2] 5b 30 [2] 64 2c }

  condition:
    any of them
}