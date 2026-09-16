rule TTP_XOR_WriteProcessMemory_ed71 {
  strings:
    $key_ed71 = { ba 03 [2] 88 21 [2] 8e 14 [2] a0 14 [2] 9f 08 }

  condition:
    any of them
}