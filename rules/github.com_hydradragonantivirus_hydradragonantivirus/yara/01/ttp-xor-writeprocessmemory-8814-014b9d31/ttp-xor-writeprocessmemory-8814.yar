rule TTP_XOR_WriteProcessMemory_8814 {
  strings:
    $key_8814 = { df 66 [2] ed 44 [2] eb 71 [2] c5 71 [2] fa 6d }

  condition:
    any of them
}