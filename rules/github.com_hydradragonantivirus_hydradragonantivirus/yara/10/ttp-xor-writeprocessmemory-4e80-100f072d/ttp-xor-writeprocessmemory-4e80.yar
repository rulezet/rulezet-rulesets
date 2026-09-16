rule TTP_XOR_WriteProcessMemory_4e80 {
  strings:
    $key_4e80 = { 19 f2 [2] 2b d0 [2] 2d e5 [2] 03 e5 [2] 3c f9 }

  condition:
    any of them
}