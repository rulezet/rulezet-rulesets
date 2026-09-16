rule TTP_XOR_WriteProcessMemory_7255 {
  strings:
    $key_7255 = { 25 27 [2] 17 05 [2] 11 30 [2] 3f 30 [2] 00 2c }

  condition:
    any of them
}