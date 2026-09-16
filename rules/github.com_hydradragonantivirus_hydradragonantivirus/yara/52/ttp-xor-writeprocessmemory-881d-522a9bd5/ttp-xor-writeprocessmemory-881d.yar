rule TTP_XOR_WriteProcessMemory_881d {
  strings:
    $key_881d = { df 6f [2] ed 4d [2] eb 78 [2] c5 78 [2] fa 64 }

  condition:
    any of them
}