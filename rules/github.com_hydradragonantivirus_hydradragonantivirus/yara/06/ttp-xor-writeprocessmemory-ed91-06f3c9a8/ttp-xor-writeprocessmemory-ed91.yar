rule TTP_XOR_WriteProcessMemory_ed91 {
  strings:
    $key_ed91 = { ba e3 [2] 88 c1 [2] 8e f4 [2] a0 f4 [2] 9f e8 }

  condition:
    any of them
}