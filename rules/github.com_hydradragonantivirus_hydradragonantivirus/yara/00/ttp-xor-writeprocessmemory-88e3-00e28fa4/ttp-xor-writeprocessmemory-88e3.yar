rule TTP_XOR_WriteProcessMemory_88e3 {
  strings:
    $key_88e3 = { df 91 [2] ed b3 [2] eb 86 [2] c5 86 [2] fa 9a }

  condition:
    any of them
}