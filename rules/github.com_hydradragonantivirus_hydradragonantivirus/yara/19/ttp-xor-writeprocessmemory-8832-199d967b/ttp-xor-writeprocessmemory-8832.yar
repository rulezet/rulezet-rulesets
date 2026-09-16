rule TTP_XOR_WriteProcessMemory_8832 {
  strings:
    $key_8832 = { df 40 [2] ed 62 [2] eb 57 [2] c5 57 [2] fa 4b }

  condition:
    any of them
}