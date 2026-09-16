rule TTP_XOR_WriteProcessMemory_ed73 {
  strings:
    $key_ed73 = { ba 01 [2] 88 23 [2] 8e 16 [2] a0 16 [2] 9f 0a }

  condition:
    any of them
}