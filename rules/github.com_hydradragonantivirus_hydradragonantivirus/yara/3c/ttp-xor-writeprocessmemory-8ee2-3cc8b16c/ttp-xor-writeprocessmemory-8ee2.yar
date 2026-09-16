rule TTP_XOR_WriteProcessMemory_8ee2 {
  strings:
    $key_8ee2 = { d9 90 [2] eb b2 [2] ed 87 [2] c3 87 [2] fc 9b }

  condition:
    any of them
}