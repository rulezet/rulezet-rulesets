rule TTP_XOR_WriteProcessMemory_8e3d {
  strings:
    $key_8e3d = { d9 4f [2] eb 6d [2] ed 58 [2] c3 58 [2] fc 44 }

  condition:
    any of them
}