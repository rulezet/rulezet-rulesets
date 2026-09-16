rule TTP_XOR_WriteProcessMemory_8ee3 {
  strings:
    $key_8ee3 = { d9 91 [2] eb b3 [2] ed 86 [2] c3 86 [2] fc 9a }

  condition:
    any of them
}