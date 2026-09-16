rule TTP_XOR_WriteProcessMemory_ed84 {
  strings:
    $key_ed84 = { ba f6 [2] 88 d4 [2] 8e e1 [2] a0 e1 [2] 9f fd }

  condition:
    any of them
}