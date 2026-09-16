rule TTP_XOR_WriteProcessMemory_88f0 {
  strings:
    $key_88f0 = { df 82 [2] ed a0 [2] eb 95 [2] c5 95 [2] fa 89 }

  condition:
    any of them
}