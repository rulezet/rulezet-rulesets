rule TTP_XOR_WriteProcessMemory_7a97 {
  strings:
    $key_7a97 = { 2d e5 [2] 1f c7 [2] 19 f2 [2] 37 f2 [2] 08 ee }

  condition:
    any of them
}