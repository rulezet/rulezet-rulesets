rule TTP_XOR_WriteProcessMemory_885e {
  strings:
    $key_885e = { df 2c [2] ed 0e [2] eb 3b [2] c5 3b [2] fa 27 }

  condition:
    any of them
}