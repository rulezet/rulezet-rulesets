rule TTP_XOR_WriteProcessMemory_8e41 {
  strings:
    $key_8e41 = { d9 33 [2] eb 11 [2] ed 24 [2] c3 24 [2] fc 38 }

  condition:
    any of them
}