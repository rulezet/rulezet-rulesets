rule TTP_XOR_WriteProcessMemory_88c8 {
  strings:
    $key_88c8 = { df ba [2] ed 98 [2] eb ad [2] c5 ad [2] fa b1 }

  condition:
    any of them
}