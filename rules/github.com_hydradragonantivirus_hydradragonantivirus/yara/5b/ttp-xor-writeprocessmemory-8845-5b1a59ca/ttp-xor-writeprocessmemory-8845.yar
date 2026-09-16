rule TTP_XOR_WriteProcessMemory_8845 {
  strings:
    $key_8845 = { df 37 [2] ed 15 [2] eb 20 [2] c5 20 [2] fa 3c }

  condition:
    any of them
}