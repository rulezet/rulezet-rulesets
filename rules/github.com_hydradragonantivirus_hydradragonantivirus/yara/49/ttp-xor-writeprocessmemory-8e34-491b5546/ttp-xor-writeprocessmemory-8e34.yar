rule TTP_XOR_WriteProcessMemory_8e34 {
  strings:
    $key_8e34 = { d9 46 [2] eb 64 [2] ed 51 [2] c3 51 [2] fc 4d }

  condition:
    any of them
}