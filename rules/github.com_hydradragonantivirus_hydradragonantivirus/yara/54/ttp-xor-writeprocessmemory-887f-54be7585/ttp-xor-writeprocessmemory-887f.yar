rule TTP_XOR_WriteProcessMemory_887f {
  strings:
    $key_887f = { df 0d [2] ed 2f [2] eb 1a [2] c5 1a [2] fa 06 }

  condition:
    any of them
}