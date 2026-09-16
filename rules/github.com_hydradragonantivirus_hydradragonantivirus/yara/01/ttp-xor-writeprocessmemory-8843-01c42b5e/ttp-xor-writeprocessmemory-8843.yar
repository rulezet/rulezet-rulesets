rule TTP_XOR_WriteProcessMemory_8843 {
  strings:
    $key_8843 = { df 31 [2] ed 13 [2] eb 26 [2] c5 26 [2] fa 3a }

  condition:
    any of them
}