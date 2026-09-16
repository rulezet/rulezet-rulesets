rule TTP_XOR_WriteProcessMemory_6f55 {
  strings:
    $key_6f55 = { 38 27 [2] 0a 05 [2] 0c 30 [2] 22 30 [2] 1d 2c }

  condition:
    any of them
}