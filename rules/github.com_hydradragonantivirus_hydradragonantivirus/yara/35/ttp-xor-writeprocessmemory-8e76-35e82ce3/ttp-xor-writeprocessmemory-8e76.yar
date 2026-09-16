rule TTP_XOR_WriteProcessMemory_8e76 {
  strings:
    $key_8e76 = { d9 04 [2] eb 26 [2] ed 13 [2] c3 13 [2] fc 0f }

  condition:
    any of them
}