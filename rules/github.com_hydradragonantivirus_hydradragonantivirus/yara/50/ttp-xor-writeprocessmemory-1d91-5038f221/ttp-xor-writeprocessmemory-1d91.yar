rule TTP_XOR_WriteProcessMemory_1d91 {
  strings:
    $key_1d91 = { 4a e3 [2] 78 c1 [2] 7e f4 [2] 50 f4 [2] 6f e8 }

  condition:
    any of them
}