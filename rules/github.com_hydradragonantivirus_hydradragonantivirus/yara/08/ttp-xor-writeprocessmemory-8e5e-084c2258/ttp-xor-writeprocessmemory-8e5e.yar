rule TTP_XOR_WriteProcessMemory_8e5e {
  strings:
    $key_8e5e = { d9 2c [2] eb 0e [2] ed 3b [2] c3 3b [2] fc 27 }

  condition:
    any of them
}