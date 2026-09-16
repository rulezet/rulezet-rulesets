rule TTP_XOR_WriteProcessMemory_3e80 {
  strings:
    $key_3e80 = { 69 f2 [2] 5b d0 [2] 5d e5 [2] 73 e5 [2] 4c f9 }

  condition:
    any of them
}