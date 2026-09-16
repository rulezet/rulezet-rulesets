rule TTP_XOR_WriteProcessMemory_8813 {
  strings:
    $key_8813 = { df 61 [2] ed 43 [2] eb 76 [2] c5 76 [2] fa 6a }

  condition:
    any of them
}