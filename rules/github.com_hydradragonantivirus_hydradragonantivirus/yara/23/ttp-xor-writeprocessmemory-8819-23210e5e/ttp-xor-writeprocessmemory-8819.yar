rule TTP_XOR_WriteProcessMemory_8819 {
  strings:
    $key_8819 = { df 6b [2] ed 49 [2] eb 7c [2] c5 7c [2] fa 60 }

  condition:
    any of them
}