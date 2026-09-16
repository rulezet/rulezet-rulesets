rule TTP_XOR_WriteProcessMemory_8840 {
  strings:
    $key_8840 = { df 32 [2] ed 10 [2] eb 25 [2] c5 25 [2] fa 39 }

  condition:
    any of them
}