rule TTP_XOR_WriteProcessMemory_8e66 {
  strings:
    $key_8e66 = { d9 14 [2] eb 36 [2] ed 03 [2] c3 03 [2] fc 1f }

  condition:
    any of them
}