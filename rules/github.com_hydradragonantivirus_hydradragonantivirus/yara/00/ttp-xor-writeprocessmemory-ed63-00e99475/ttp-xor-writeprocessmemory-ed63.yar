rule TTP_XOR_WriteProcessMemory_ed63 {
  strings:
    $key_ed63 = { ba 11 [2] 88 33 [2] 8e 06 [2] a0 06 [2] 9f 1a }

  condition:
    any of them
}