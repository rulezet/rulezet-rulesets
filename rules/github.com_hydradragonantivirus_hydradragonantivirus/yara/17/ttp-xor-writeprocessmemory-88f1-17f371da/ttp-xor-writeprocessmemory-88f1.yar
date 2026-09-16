rule TTP_XOR_WriteProcessMemory_88f1 {
  strings:
    $key_88f1 = { df 83 [2] ed a1 [2] eb 94 [2] c5 94 [2] fa 88 }

  condition:
    any of them
}