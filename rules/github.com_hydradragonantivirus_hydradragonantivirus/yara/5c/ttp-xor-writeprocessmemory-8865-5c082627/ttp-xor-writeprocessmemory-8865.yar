rule TTP_XOR_WriteProcessMemory_8865 {
  strings:
    $key_8865 = { df 17 [2] ed 35 [2] eb 00 [2] c5 00 [2] fa 1c }

  condition:
    any of them
}