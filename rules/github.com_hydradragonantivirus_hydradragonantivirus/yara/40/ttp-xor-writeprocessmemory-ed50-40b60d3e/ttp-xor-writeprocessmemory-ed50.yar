rule TTP_XOR_WriteProcessMemory_ed50 {
  strings:
    $key_ed50 = { ba 22 [2] 88 00 [2] 8e 35 [2] a0 35 [2] 9f 29 }

  condition:
    any of them
}