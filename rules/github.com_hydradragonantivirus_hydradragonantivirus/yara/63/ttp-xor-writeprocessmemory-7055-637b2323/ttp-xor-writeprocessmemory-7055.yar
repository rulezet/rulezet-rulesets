rule TTP_XOR_WriteProcessMemory_7055 {
  strings:
    $key_7055 = { 27 27 [2] 15 05 [2] 13 30 [2] 3d 30 [2] 02 2c }

  condition:
    any of them
}