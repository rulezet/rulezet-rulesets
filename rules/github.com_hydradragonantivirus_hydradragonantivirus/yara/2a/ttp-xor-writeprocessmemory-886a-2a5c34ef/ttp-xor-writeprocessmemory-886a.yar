rule TTP_XOR_WriteProcessMemory_886a {
  strings:
    $key_886a = { df 18 [2] ed 3a [2] eb 0f [2] c5 0f [2] fa 13 }

  condition:
    any of them
}