rule TTP_XOR_WriteProcessMemory_8e2d {
  strings:
    $key_8e2d = { d9 5f [2] eb 7d [2] ed 48 [2] c3 48 [2] fc 54 }

  condition:
    any of them
}