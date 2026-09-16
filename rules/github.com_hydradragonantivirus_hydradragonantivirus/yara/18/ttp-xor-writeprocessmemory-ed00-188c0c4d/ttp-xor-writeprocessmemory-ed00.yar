rule TTP_XOR_WriteProcessMemory_ed00 {
  strings:
    $key_ed00 = { ba 72 [2] 88 50 [2] 8e 65 [2] a0 65 [2] 9f 79 }

  condition:
    any of them
}