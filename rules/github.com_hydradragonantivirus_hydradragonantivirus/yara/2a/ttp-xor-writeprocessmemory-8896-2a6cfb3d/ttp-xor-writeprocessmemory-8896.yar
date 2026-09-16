rule TTP_XOR_WriteProcessMemory_8896 {
  strings:
    $key_8896 = { df e4 [2] ed c6 [2] eb f3 [2] c5 f3 [2] fa ef }

  condition:
    any of them
}