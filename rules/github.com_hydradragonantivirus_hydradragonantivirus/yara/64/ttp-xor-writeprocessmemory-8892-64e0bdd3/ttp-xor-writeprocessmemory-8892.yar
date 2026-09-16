rule TTP_XOR_WriteProcessMemory_8892 {
  strings:
    $key_8892 = { df e0 [2] ed c2 [2] eb f7 [2] c5 f7 [2] fa eb }

  condition:
    any of them
}