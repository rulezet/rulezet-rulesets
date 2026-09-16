rule TTP_XOR_WriteProcessMemory_8836 {
  strings:
    $key_8836 = { df 44 [2] ed 66 [2] eb 53 [2] c5 53 [2] fa 4f }

  condition:
    any of them
}