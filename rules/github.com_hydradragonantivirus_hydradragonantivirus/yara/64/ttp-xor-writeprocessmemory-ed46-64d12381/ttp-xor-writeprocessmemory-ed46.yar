rule TTP_XOR_WriteProcessMemory_ed46 {
  strings:
    $key_ed46 = { ba 34 [2] 88 16 [2] 8e 23 [2] a0 23 [2] 9f 3f }

  condition:
    any of them
}