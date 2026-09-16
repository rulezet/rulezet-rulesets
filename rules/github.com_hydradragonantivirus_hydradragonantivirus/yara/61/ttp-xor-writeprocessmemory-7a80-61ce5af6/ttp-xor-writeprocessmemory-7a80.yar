rule TTP_XOR_WriteProcessMemory_7a80 {
  strings:
    $key_7a80 = { 2d f2 [2] 1f d0 [2] 19 e5 [2] 37 e5 [2] 08 f9 }

  condition:
    any of them
}