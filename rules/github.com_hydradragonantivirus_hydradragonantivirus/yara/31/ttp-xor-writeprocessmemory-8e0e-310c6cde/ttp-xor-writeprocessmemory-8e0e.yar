rule TTP_XOR_WriteProcessMemory_8e0e {
  strings:
    $key_8e0e = { d9 7c [2] eb 5e [2] ed 6b [2] c3 6b [2] fc 77 }

  condition:
    any of them
}