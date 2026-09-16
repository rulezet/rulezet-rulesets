rule TTP_XOR_WriteProcessMemory_6096 {
  strings:
    $key_6096 = { 37 e4 [2] 05 c6 [2] 03 f3 [2] 2d f3 [2] 12 ef }

  condition:
    any of them
}