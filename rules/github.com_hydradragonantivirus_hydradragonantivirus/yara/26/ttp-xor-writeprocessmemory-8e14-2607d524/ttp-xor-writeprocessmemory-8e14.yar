rule TTP_XOR_WriteProcessMemory_8e14 {
  strings:
    $key_8e14 = { d9 66 [2] eb 44 [2] ed 71 [2] c3 71 [2] fc 6d }

  condition:
    any of them
}