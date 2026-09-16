rule TTP_XOR_WriteProcessMemory_8849 {
  strings:
    $key_8849 = { df 3b [2] ed 19 [2] eb 2c [2] c5 2c [2] fa 30 }

  condition:
    any of them
}