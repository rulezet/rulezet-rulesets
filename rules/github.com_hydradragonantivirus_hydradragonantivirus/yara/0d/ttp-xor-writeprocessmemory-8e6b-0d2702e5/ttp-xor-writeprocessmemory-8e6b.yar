rule TTP_XOR_WriteProcessMemory_8e6b {
  strings:
    $key_8e6b = { d9 19 [2] eb 3b [2] ed 0e [2] c3 0e [2] fc 12 }

  condition:
    any of them
}