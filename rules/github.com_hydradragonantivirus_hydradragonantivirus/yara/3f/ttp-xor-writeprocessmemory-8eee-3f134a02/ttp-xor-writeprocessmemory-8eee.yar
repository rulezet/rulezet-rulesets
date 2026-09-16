rule TTP_XOR_WriteProcessMemory_8eee {
  strings:
    $key_8eee = { d9 9c [2] eb be [2] ed 8b [2] c3 8b [2] fc 97 }

  condition:
    any of them
}