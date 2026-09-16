rule TTP_XOR_WriteProcessMemory_8804 {
  strings:
    $key_8804 = { df 76 [2] ed 54 [2] eb 61 [2] c5 61 [2] fa 7d }

  condition:
    any of them
}