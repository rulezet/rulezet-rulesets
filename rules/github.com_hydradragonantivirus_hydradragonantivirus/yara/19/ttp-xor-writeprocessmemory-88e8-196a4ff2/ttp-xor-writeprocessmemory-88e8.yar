rule TTP_XOR_WriteProcessMemory_88e8 {
  strings:
    $key_88e8 = { df 9a [2] ed b8 [2] eb 8d [2] c5 8d [2] fa 91 }

  condition:
    any of them
}