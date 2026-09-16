rule TTP_XOR_WriteProcessMemory_8e0c {
  strings:
    $key_8e0c = { d9 7e [2] eb 5c [2] ed 69 [2] c3 69 [2] fc 75 }

  condition:
    any of them
}