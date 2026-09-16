rule TTP_XOR_WriteProcessMemory_4591 {
  strings:
    $key_4591 = { 12 e3 [2] 20 c1 [2] 26 f4 [2] 08 f4 [2] 37 e8 }

  condition:
    any of them
}