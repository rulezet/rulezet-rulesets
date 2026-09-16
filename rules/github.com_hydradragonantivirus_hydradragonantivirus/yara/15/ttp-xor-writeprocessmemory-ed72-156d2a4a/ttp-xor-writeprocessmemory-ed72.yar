rule TTP_XOR_WriteProcessMemory_ed72 {
  strings:
    $key_ed72 = { ba 00 [2] 88 22 [2] 8e 17 [2] a0 17 [2] 9f 0b }

  condition:
    any of them
}