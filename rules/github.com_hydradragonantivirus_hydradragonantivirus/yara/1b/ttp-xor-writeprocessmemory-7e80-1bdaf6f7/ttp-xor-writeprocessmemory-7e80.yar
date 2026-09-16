rule TTP_XOR_WriteProcessMemory_7e80 {
  strings:
    $key_7e80 = { 29 f2 [2] 1b d0 [2] 1d e5 [2] 33 e5 [2] 0c f9 }

  condition:
    any of them
}