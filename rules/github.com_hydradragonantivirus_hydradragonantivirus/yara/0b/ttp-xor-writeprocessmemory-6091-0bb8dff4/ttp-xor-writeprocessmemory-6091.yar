rule TTP_XOR_WriteProcessMemory_6091 {
  strings:
    $key_6091 = { 37 e3 [2] 05 c1 [2] 03 f4 [2] 2d f4 [2] 12 e8 }

  condition:
    any of them
}