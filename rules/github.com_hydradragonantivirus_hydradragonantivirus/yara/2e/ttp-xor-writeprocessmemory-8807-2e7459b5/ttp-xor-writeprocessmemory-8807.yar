rule TTP_XOR_WriteProcessMemory_8807 {
  strings:
    $key_8807 = { df 75 [2] ed 57 [2] eb 62 [2] c5 62 [2] fa 7e }

  condition:
    any of them
}