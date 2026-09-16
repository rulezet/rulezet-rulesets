rule TTP_XOR_WriteProcessMemory_4d91 {
  strings:
    $key_4d91 = { 1a e3 [2] 28 c1 [2] 2e f4 [2] 00 f4 [2] 3f e8 }

  condition:
    any of them
}