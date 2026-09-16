rule TTP_XOR_WriteProcessMemory_88c0 {
  strings:
    $key_88c0 = { df b2 [2] ed 90 [2] eb a5 [2] c5 a5 [2] fa b9 }

  condition:
    any of them
}