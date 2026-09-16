rule TTP_XOR_WriteProcessMemory_ed45 {
  strings:
    $key_ed45 = { ba 37 [2] 88 15 [2] 8e 20 [2] a0 20 [2] 9f 3c }

  condition:
    any of them
}