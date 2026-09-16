rule TTP_XOR_WriteProcessMemory_88c5 {
  strings:
    $key_88c5 = { df b7 [2] ed 95 [2] eb a0 [2] c5 a0 [2] fa bc }

  condition:
    any of them
}