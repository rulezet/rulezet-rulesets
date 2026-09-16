rule TTP_XOR_WriteProcessMemory_8851 {
  strings:
    $key_8851 = { df 23 [2] ed 01 [2] eb 34 [2] c5 34 [2] fa 28 }

  condition:
    any of them
}