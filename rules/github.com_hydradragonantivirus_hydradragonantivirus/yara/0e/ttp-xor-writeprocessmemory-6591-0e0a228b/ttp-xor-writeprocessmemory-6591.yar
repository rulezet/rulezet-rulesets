rule TTP_XOR_WriteProcessMemory_6591 {
  strings:
    $key_6591 = { 32 e3 [2] 00 c1 [2] 06 f4 [2] 28 f4 [2] 17 e8 }

  condition:
    any of them
}