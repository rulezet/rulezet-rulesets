rule TTP_XOR_WriteProcessMemory_8e5b {
  strings:
    $key_8e5b = { d9 29 [2] eb 0b [2] ed 3e [2] c3 3e [2] fc 22 }

  condition:
    any of them
}