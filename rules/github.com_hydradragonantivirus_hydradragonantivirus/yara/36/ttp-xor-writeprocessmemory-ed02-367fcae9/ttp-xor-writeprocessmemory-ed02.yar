rule TTP_XOR_WriteProcessMemory_ed02 {
  strings:
    $key_ed02 = { ba 70 [2] 88 52 [2] 8e 67 [2] a0 67 [2] 9f 7b }

  condition:
    any of them
}