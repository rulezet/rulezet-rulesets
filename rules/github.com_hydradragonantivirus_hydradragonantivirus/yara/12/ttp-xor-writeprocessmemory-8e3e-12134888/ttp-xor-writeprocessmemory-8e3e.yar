rule TTP_XOR_WriteProcessMemory_8e3e {
  strings:
    $key_8e3e = { d9 4c [2] eb 6e [2] ed 5b [2] c3 5b [2] fc 47 }

  condition:
    any of them
}