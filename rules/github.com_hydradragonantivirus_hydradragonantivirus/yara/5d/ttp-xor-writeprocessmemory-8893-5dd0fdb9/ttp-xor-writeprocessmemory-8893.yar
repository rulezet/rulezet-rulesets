rule TTP_XOR_WriteProcessMemory_8893 {
  strings:
    $key_8893 = { df e1 [2] ed c3 [2] eb f6 [2] c5 f6 [2] fa ea }

  condition:
    any of them
}