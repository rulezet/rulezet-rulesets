rule TTP_XOR_WriteProcessMemory_8ef6 {
  strings:
    $key_8ef6 = { d9 84 [2] eb a6 [2] ed 93 [2] c3 93 [2] fc 8f }

  condition:
    any of them
}