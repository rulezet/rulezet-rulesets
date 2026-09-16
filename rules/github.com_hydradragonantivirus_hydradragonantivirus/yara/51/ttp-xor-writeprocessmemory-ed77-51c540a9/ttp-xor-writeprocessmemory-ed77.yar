rule TTP_XOR_WriteProcessMemory_ed77 {
  strings:
    $key_ed77 = { ba 05 [2] 88 27 [2] 8e 12 [2] a0 12 [2] 9f 0e }

  condition:
    any of them
}