rule TTP_XOR_WriteProcessMemory_2391 {
  strings:
    $key_2391 = { 74 e3 [2] 46 c1 [2] 40 f4 [2] 6e f4 [2] 51 e8 }

  condition:
    any of them
}