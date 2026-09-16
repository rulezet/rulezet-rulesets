rule TTP_XOR_WriteProcessMemory_8e27 {
  strings:
    $key_8e27 = { d9 55 [2] eb 77 [2] ed 42 [2] c3 42 [2] fc 5e }

  condition:
    any of them
}