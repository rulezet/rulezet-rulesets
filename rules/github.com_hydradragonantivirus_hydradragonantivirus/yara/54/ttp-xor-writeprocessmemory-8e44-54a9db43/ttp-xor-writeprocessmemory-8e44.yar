rule TTP_XOR_WriteProcessMemory_8e44 {
  strings:
    $key_8e44 = { d9 36 [2] eb 14 [2] ed 21 [2] c3 21 [2] fc 3d }

  condition:
    any of them
}