rule TTP_XOR_WriteProcessMemory_88f3 {
  strings:
    $key_88f3 = { df 81 [2] ed a3 [2] eb 96 [2] c5 96 [2] fa 8a }

  condition:
    any of them
}