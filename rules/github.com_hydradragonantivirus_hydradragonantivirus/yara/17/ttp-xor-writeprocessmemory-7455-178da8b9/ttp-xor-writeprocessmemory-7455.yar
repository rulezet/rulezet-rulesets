rule TTP_XOR_WriteProcessMemory_7455 {
  strings:
    $key_7455 = { 23 27 [2] 11 05 [2] 17 30 [2] 39 30 [2] 06 2c }

  condition:
    any of them
}