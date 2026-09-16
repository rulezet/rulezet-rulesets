rule TTP_XOR_WriteProcessMemory_1191 {
  strings:
    $key_1191 = { 46 e3 [2] 74 c1 [2] 72 f4 [2] 5c f4 [2] 63 e8 }

  condition:
    any of them
}