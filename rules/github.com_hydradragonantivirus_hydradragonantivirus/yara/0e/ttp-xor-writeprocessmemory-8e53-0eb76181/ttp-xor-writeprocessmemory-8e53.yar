rule TTP_XOR_WriteProcessMemory_8e53 {
  strings:
    $key_8e53 = { d9 21 [2] eb 03 [2] ed 36 [2] c3 36 [2] fc 2a }

  condition:
    any of them
}