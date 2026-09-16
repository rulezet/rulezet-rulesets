rule TTP_XOR_WriteProcessMemory_887c {
  strings:
    $key_887c = { df 0e [2] ed 2c [2] eb 19 [2] c5 19 [2] fa 05 }

  condition:
    any of them
}