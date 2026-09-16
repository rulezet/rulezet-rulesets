rule TTP_XOR_WriteProcessMemory_8e48 {
  strings:
    $key_8e48 = { d9 3a [2] eb 18 [2] ed 2d [2] c3 2d [2] fc 31 }

  condition:
    any of them
}