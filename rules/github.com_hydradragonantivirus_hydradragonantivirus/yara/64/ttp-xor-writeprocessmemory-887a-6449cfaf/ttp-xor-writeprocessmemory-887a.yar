rule TTP_XOR_WriteProcessMemory_887a {
  strings:
    $key_887a = { df 08 [2] ed 2a [2] eb 1f [2] c5 1f [2] fa 03 }

  condition:
    any of them
}