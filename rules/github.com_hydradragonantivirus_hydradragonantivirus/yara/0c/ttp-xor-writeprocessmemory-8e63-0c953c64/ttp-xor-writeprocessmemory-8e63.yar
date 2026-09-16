rule TTP_XOR_WriteProcessMemory_8e63 {
  strings:
    $key_8e63 = { d9 11 [2] eb 33 [2] ed 06 [2] c3 06 [2] fc 1a }

  condition:
    any of them
}