rule TTP_XOR_WriteProcessMemory_8e6c {
  strings:
    $key_8e6c = { d9 1e [2] eb 3c [2] ed 09 [2] c3 09 [2] fc 15 }

  condition:
    any of them
}