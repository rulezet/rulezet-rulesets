rule TTP_XOR_WriteProcessMemory_8e51 {
  strings:
    $key_8e51 = { d9 23 [2] eb 01 [2] ed 34 [2] c3 34 [2] fc 28 }

  condition:
    any of them
}