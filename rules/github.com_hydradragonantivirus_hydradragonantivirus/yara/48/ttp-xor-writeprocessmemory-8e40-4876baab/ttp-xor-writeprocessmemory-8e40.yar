rule TTP_XOR_WriteProcessMemory_8e40 {
  strings:
    $key_8e40 = { d9 32 [2] eb 10 [2] ed 25 [2] c3 25 [2] fc 39 }

  condition:
    any of them
}