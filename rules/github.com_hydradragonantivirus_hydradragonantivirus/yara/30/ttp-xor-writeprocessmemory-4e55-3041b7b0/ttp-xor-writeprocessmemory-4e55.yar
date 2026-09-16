rule TTP_XOR_WriteProcessMemory_4e55 {
  strings:
    $key_4e55 = { 19 27 [2] 2b 05 [2] 2d 30 [2] 03 30 [2] 3c 2c }

  condition:
    any of them
}