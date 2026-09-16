rule TTP_XOR_WriteProcessMemory_8e5d {
  strings:
    $key_8e5d = { d9 2f [2] eb 0d [2] ed 38 [2] c3 38 [2] fc 24 }

  condition:
    any of them
}