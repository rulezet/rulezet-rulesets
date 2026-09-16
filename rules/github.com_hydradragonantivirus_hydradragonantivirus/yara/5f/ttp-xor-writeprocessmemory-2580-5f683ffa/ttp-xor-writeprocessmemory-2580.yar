rule TTP_XOR_WriteProcessMemory_2580 {
  strings:
    $key_2580 = { 72 f2 [2] 40 d0 [2] 46 e5 [2] 68 e5 [2] 57 f9 }

  condition:
    any of them
}