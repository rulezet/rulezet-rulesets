rule TTP_XOR_WriteProcessMemory_8e4d {
  strings:
    $key_8e4d = { d9 3f [2] eb 1d [2] ed 28 [2] c3 28 [2] fc 34 }

  condition:
    any of them
}