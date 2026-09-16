rule TTP_XOR_WriteProcessMemory_8863 {
  strings:
    $key_8863 = { df 11 [2] ed 33 [2] eb 06 [2] c5 06 [2] fa 1a }

  condition:
    any of them
}