rule TTP_XOR_WriteProcessMemory_8e1e {
  strings:
    $key_8e1e = { d9 6c [2] eb 4e [2] ed 7b [2] c3 7b [2] fc 67 }

  condition:
    any of them
}