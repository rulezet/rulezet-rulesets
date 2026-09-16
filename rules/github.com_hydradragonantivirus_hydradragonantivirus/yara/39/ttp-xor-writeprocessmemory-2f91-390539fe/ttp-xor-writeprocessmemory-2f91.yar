rule TTP_XOR_WriteProcessMemory_2f91 {
  strings:
    $key_2f91 = { 78 e3 [2] 4a c1 [2] 4c f4 [2] 62 f4 [2] 5d e8 }

  condition:
    any of them
}