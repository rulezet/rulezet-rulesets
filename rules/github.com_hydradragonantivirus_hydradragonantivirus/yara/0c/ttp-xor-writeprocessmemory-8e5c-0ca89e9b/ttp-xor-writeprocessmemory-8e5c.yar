rule TTP_XOR_WriteProcessMemory_8e5c {
  strings:
    $key_8e5c = { d9 2e [2] eb 0c [2] ed 39 [2] c3 39 [2] fc 25 }

  condition:
    any of them
}