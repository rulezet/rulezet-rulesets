rule TTP_XOR_WriteProcessMemory_8e05 {
  strings:
    $key_8e05 = { d9 77 [2] eb 55 [2] ed 60 [2] c3 60 [2] fc 7c }

  condition:
    any of them
}