rule TTP_XOR_WriteProcessMemory_8873 {
  strings:
    $key_8873 = { df 01 [2] ed 23 [2] eb 16 [2] c5 16 [2] fa 0a }

  condition:
    any of them
}