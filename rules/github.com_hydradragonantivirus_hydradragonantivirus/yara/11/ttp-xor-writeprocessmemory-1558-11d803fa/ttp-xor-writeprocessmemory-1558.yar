rule TTP_XOR_WriteProcessMemory_1558 {
  strings:
    $key_1558 = { 42 2a [2] 70 08 [2] 76 3d [2] 58 3d [2] 67 21 }

  condition:
    any of them
}