rule TTP_XOR_WriteProcessMemory_885c {
  strings:
    $key_885c = { df 2e [2] ed 0c [2] eb 39 [2] c5 39 [2] fa 25 }

  condition:
    any of them
}