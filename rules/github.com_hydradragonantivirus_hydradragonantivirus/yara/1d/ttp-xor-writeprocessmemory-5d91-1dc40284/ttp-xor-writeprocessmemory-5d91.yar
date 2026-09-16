rule TTP_XOR_WriteProcessMemory_5d91 {
  strings:
    $key_5d91 = { 0a e3 [2] 38 c1 [2] 3e f4 [2] 10 f4 [2] 2f e8 }

  condition:
    any of them
}