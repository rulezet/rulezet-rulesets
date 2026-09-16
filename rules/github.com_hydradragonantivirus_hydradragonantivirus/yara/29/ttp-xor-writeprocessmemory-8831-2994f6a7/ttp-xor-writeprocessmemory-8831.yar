rule TTP_XOR_WriteProcessMemory_8831 {
  strings:
    $key_8831 = { df 43 [2] ed 61 [2] eb 54 [2] c5 54 [2] fa 48 }

  condition:
    any of them
}