rule TTP_XOR_WriteProcessMemory_8862 {
  strings:
    $key_8862 = { df 10 [2] ed 32 [2] eb 07 [2] c5 07 [2] fa 1b }

  condition:
    any of them
}