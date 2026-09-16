rule TTP_XOR_WriteProcessMemory_8e16 {
  strings:
    $key_8e16 = { d9 64 [2] eb 46 [2] ed 73 [2] c3 73 [2] fc 6f }

  condition:
    any of them
}