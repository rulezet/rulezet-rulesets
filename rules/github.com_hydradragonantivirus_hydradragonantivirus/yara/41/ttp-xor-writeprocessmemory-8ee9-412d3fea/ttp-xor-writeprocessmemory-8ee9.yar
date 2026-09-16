rule TTP_XOR_WriteProcessMemory_8ee9 {
  strings:
    $key_8ee9 = { d9 9b [2] eb b9 [2] ed 8c [2] c3 8c [2] fc 90 }

  condition:
    any of them
}