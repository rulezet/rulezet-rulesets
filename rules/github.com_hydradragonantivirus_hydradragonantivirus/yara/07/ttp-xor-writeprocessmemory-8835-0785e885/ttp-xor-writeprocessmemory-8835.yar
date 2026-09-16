rule TTP_XOR_WriteProcessMemory_8835 {
  strings:
    $key_8835 = { df 47 [2] ed 65 [2] eb 50 [2] c5 50 [2] fa 4c }

  condition:
    any of them
}