rule TTP_XOR_WriteProcessMemory_5591 {
  strings:
    $key_5591 = { 02 e3 [2] 30 c1 [2] 36 f4 [2] 18 f4 [2] 27 e8 }

  condition:
    any of them
}