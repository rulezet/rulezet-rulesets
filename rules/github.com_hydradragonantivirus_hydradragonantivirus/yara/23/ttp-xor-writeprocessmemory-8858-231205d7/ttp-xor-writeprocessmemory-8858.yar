rule TTP_XOR_WriteProcessMemory_8858 {
  strings:
    $key_8858 = { df 2a [2] ed 08 [2] eb 3d [2] c5 3d [2] fa 21 }

  condition:
    any of them
}