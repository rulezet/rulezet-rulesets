rule TTP_XOR_WriteProcessMemory_8872 {
  strings:
    $key_8872 = { df 00 [2] ed 22 [2] eb 17 [2] c5 17 [2] fa 0b }

  condition:
    any of them
}