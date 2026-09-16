rule TTP_XOR_WriteProcessMemory_6255 {
  strings:
    $key_6255 = { 35 27 [2] 07 05 [2] 01 30 [2] 2f 30 [2] 10 2c }

  condition:
    any of them
}