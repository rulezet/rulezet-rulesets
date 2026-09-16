rule TTP_XOR_WriteProcessMemory_88c9 {
  strings:
    $key_88c9 = { df bb [2] ed 99 [2] eb ac [2] c5 ac [2] fa b0 }

  condition:
    any of them
}