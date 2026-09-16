rule TTP_XOR_WriteProcessMemory_6145 {
  strings:
    $key_6145 = { 36 37 [2] 04 15 [2] 02 20 [2] 2c 20 [2] 13 3c }

  condition:
    any of them
}