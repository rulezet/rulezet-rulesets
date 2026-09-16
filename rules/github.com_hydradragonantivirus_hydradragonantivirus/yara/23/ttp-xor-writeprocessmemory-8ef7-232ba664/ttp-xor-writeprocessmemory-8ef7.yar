rule TTP_XOR_WriteProcessMemory_8ef7 {
  strings:
    $key_8ef7 = { d9 85 [2] eb a7 [2] ed 92 [2] c3 92 [2] fc 8e }

  condition:
    any of them
}