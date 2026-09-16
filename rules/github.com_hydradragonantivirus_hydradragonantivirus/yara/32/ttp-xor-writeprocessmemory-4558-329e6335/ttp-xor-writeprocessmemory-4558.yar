rule TTP_XOR_WriteProcessMemory_4558 {
  strings:
    $key_4558 = { 12 2a [2] 20 08 [2] 26 3d [2] 08 3d [2] 37 21 }

  condition:
    any of them
}