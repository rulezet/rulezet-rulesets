rule TTP_XOR_WriteProcessMemory_1d55 {
  strings:
    $key_1d55 = { 4a 27 [2] 78 05 [2] 7e 30 [2] 50 30 [2] 6f 2c }

  condition:
    any of them
}