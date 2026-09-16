rule TTP_XOR_WriteProcessMemory_1c55 {
  strings:
    $key_1c55 = { 4b 27 [2] 79 05 [2] 7f 30 [2] 51 30 [2] 6e 2c }

  condition:
    any of them
}