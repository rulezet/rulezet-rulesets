rule TTP_XOR_WriteProcessMemory_8e32 {
  strings:
    $key_8e32 = { d9 40 [2] eb 62 [2] ed 57 [2] c3 57 [2] fc 4b }

  condition:
    any of them
}