rule TTP_XOR_WriteProcessMemory_8e0b {
  strings:
    $key_8e0b = { d9 79 [2] eb 5b [2] ed 6e [2] c3 6e [2] fc 72 }

  condition:
    any of them
}