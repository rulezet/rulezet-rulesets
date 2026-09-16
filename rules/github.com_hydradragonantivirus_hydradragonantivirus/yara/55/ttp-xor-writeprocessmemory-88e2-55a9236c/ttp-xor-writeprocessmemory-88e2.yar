rule TTP_XOR_WriteProcessMemory_88e2 {
  strings:
    $key_88e2 = { df 90 [2] ed b2 [2] eb 87 [2] c5 87 [2] fa 9b }

  condition:
    any of them
}