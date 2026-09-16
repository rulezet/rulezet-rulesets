rule TTP_XOR_WriteProcessMemory_882b {
  strings:
    $key_882b = { df 59 [2] ed 7b [2] eb 4e [2] c5 4e [2] fa 52 }

  condition:
    any of them
}