rule TTP_XOR_WriteProcessMemory_25c1 {
  strings:
    $key_25c1 = { 72 b3 [2] 40 91 [2] 46 a4 [2] 68 a4 [2] 57 b8 }

  condition:
    any of them
}