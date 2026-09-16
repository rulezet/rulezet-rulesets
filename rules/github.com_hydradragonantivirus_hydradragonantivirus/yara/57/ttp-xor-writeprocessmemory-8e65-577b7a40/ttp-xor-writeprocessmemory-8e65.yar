rule TTP_XOR_WriteProcessMemory_8e65 {
  strings:
    $key_8e65 = { d9 17 [2] eb 35 [2] ed 00 [2] c3 00 [2] fc 1c }

  condition:
    any of them
}