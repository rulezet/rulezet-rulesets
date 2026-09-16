rule TTP_XOR_WriteProcessMemory_2d55 {
  strings:
    $key_2d55 = { 7a 27 [2] 48 05 [2] 4e 30 [2] 60 30 [2] 5f 2c }

  condition:
    any of them
}