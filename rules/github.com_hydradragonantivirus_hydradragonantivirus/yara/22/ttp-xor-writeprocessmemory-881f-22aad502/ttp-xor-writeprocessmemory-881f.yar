rule TTP_XOR_WriteProcessMemory_881f {
  strings:
    $key_881f = { df 6d [2] ed 4f [2] eb 7a [2] c5 7a [2] fa 66 }

  condition:
    any of them
}