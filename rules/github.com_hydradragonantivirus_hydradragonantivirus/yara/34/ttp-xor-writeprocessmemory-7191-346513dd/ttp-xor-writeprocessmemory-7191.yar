rule TTP_XOR_WriteProcessMemory_7191 {
  strings:
    $key_7191 = { 26 e3 [2] 14 c1 [2] 12 f4 [2] 3c f4 [2] 03 e8 }

  condition:
    any of them
}