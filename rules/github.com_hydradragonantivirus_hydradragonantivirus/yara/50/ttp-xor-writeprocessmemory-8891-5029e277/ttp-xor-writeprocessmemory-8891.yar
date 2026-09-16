rule TTP_XOR_WriteProcessMemory_8891 {
  strings:
    $key_8891 = { df e3 [2] ed c1 [2] eb f4 [2] c5 f4 [2] fa e8 }

  condition:
    any of them
}