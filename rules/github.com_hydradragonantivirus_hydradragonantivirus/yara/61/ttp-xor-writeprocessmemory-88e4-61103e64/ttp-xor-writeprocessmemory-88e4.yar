rule TTP_XOR_WriteProcessMemory_88e4 {
  strings:
    $key_88e4 = { df 96 [2] ed b4 [2] eb 81 [2] c5 81 [2] fa 9d }

  condition:
    any of them
}