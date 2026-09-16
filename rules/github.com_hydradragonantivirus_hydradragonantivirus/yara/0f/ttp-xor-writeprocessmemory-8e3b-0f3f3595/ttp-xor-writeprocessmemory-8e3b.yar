rule TTP_XOR_WriteProcessMemory_8e3b {
  strings:
    $key_8e3b = { d9 49 [2] eb 6b [2] ed 5e [2] c3 5e [2] fc 42 }

  condition:
    any of them
}