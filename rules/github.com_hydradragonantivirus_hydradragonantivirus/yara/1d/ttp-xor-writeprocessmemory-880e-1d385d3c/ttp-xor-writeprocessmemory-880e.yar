rule TTP_XOR_WriteProcessMemory_880e {
  strings:
    $key_880e = { df 7c [2] ed 5e [2] eb 6b [2] c5 6b [2] fa 77 }

  condition:
    any of them
}