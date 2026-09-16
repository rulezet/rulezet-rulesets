rule TTP_XOR_WriteProcessMemory_8868 {
  strings:
    $key_8868 = { df 1a [2] ed 38 [2] eb 0d [2] c5 0d [2] fa 11 }

  condition:
    any of them
}