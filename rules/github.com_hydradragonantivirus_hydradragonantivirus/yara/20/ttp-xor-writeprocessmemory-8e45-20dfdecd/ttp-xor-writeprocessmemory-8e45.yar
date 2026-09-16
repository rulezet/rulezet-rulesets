rule TTP_XOR_WriteProcessMemory_8e45 {
  strings:
    $key_8e45 = { d9 37 [2] eb 15 [2] ed 20 [2] c3 20 [2] fc 3c }

  condition:
    any of them
}