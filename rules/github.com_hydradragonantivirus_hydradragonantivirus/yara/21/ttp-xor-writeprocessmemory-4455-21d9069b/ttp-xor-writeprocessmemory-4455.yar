rule TTP_XOR_WriteProcessMemory_4455 {
  strings:
    $key_4455 = { 13 27 [2] 21 05 [2] 27 30 [2] 09 30 [2] 36 2c }

  condition:
    any of them
}