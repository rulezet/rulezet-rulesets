rule TTP_XOR_WriteProcessMemory_880b {
  strings:
    $key_880b = { df 79 [2] ed 5b [2] eb 6e [2] c5 6e [2] fa 72 }

  condition:
    any of them
}