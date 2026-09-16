rule TTP_XOR_WriteProcessMemory_8812 {
  strings:
    $key_8812 = { df 60 [2] ed 42 [2] eb 77 [2] c5 77 [2] fa 6b }

  condition:
    any of them
}