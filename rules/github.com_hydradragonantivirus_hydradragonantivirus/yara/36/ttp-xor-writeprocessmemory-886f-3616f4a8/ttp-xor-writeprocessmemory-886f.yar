rule TTP_XOR_WriteProcessMemory_886f {
  strings:
    $key_886f = { df 1d [2] ed 3f [2] eb 0a [2] c5 0a [2] fa 16 }

  condition:
    any of them
}