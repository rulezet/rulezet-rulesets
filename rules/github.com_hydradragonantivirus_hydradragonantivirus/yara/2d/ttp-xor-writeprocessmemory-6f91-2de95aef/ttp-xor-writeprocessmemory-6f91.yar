rule TTP_XOR_WriteProcessMemory_6f91 {
  strings:
    $key_6f91 = { 38 e3 [2] 0a c1 [2] 0c f4 [2] 22 f4 [2] 1d e8 }

  condition:
    any of them
}