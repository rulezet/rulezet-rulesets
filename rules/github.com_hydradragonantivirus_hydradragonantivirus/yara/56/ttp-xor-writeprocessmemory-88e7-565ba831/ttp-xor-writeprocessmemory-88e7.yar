rule TTP_XOR_WriteProcessMemory_88e7 {
  strings:
    $key_88e7 = { df 95 [2] ed b7 [2] eb 82 [2] c5 82 [2] fa 9e }

  condition:
    any of them
}