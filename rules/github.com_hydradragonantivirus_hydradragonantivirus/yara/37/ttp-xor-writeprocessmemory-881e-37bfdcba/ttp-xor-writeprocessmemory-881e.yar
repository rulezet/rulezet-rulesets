rule TTP_XOR_WriteProcessMemory_881e {
  strings:
    $key_881e = { df 6c [2] ed 4e [2] eb 7b [2] c5 7b [2] fa 67 }

  condition:
    any of them
}