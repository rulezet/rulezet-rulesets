rule TTP_XOR_WriteProcessMemory_8e62 {
  strings:
    $key_8e62 = { d9 10 [2] eb 32 [2] ed 07 [2] c3 07 [2] fc 1b }

  condition:
    any of them
}