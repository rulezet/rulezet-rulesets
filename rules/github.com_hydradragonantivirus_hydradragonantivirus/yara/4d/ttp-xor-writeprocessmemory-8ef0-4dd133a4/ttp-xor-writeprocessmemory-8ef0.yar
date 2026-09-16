rule TTP_XOR_WriteProcessMemory_8ef0 {
  strings:
    $key_8ef0 = { d9 82 [2] eb a0 [2] ed 95 [2] c3 95 [2] fc 89 }

  condition:
    any of them
}