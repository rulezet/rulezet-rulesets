rule TTP_XOR_WriteProcessMemory_8841 {
  strings:
    $key_8841 = { df 33 [2] ed 11 [2] eb 24 [2] c5 24 [2] fa 38 }

  condition:
    any of them
}