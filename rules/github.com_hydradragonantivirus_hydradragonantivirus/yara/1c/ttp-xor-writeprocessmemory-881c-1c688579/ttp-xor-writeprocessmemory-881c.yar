rule TTP_XOR_WriteProcessMemory_881c {
  strings:
    $key_881c = { df 6e [2] ed 4c [2] eb 79 [2] c5 79 [2] fa 65 }

  condition:
    any of them
}