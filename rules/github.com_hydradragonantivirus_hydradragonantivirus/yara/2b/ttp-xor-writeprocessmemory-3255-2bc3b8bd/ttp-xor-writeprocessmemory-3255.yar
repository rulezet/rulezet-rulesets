rule TTP_XOR_WriteProcessMemory_3255 {
  strings:
    $key_3255 = { 65 27 [2] 57 05 [2] 51 30 [2] 7f 30 [2] 40 2c }

  condition:
    any of them
}