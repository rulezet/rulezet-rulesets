rule TTP_XOR_WriteProcessMemory_8824 {
  strings:
    $key_8824 = { df 56 [2] ed 74 [2] eb 41 [2] c5 41 [2] fa 5d }

  condition:
    any of them
}