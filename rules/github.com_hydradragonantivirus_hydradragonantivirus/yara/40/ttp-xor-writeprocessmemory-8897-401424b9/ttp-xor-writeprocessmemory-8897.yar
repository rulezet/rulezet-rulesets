rule TTP_XOR_WriteProcessMemory_8897 {
  strings:
    $key_8897 = { df e5 [2] ed c7 [2] eb f2 [2] c5 f2 [2] fa ee }

  condition:
    any of them
}