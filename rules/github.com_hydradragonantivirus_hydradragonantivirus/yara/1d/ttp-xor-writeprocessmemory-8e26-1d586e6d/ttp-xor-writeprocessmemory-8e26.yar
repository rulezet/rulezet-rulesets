rule TTP_XOR_WriteProcessMemory_8e26 {
  strings:
    $key_8e26 = { d9 54 [2] eb 76 [2] ed 43 [2] c3 43 [2] fc 5f }

  condition:
    any of them
}