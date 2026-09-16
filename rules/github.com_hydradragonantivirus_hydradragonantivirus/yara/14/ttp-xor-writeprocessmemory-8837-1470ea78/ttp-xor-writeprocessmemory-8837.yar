rule TTP_XOR_WriteProcessMemory_8837 {
  strings:
    $key_8837 = { df 45 [2] ed 67 [2] eb 52 [2] c5 52 [2] fa 4e }

  condition:
    any of them
}