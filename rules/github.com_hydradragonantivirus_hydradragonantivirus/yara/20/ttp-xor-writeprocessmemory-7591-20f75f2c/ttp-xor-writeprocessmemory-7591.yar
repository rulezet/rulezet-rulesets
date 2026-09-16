rule TTP_XOR_WriteProcessMemory_7591 {
  strings:
    $key_7591 = { 22 e3 [2] 10 c1 [2] 16 f4 [2] 38 f4 [2] 07 e8 }

  condition:
    any of them
}