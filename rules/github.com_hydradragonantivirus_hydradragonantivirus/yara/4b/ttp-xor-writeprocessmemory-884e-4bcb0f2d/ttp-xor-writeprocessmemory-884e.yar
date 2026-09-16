rule TTP_XOR_WriteProcessMemory_884e {
  strings:
    $key_884e = { df 3c [2] ed 1e [2] eb 2b [2] c5 2b [2] fa 37 }

  condition:
    any of them
}