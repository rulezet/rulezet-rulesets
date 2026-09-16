rule TTP_XOR_WriteProcessMemory_4f55 {
  strings:
    $key_4f55 = { 18 27 [2] 2a 05 [2] 2c 30 [2] 02 30 [2] 3d 2c }

  condition:
    any of them
}