rule TTP_XOR_WriteProcessMemory_881b {
  strings:
    $key_881b = { df 69 [2] ed 4b [2] eb 7e [2] c5 7e [2] fa 62 }

  condition:
    any of them
}