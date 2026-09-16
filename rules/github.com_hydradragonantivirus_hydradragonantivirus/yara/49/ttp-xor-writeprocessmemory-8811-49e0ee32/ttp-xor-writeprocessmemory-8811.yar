rule TTP_XOR_WriteProcessMemory_8811 {
  strings:
    $key_8811 = { df 63 [2] ed 41 [2] eb 74 [2] c5 74 [2] fa 68 }

  condition:
    any of them
}