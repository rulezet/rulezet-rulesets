rule TTP_XOR_WriteProcessMemory_88f6 {
  strings:
    $key_88f6 = { df 84 [2] ed a6 [2] eb 93 [2] c5 93 [2] fa 8f }

  condition:
    any of them
}