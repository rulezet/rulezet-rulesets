rule TTP_XOR_WriteProcessMemory_8e67 {
  strings:
    $key_8e67 = { d9 15 [2] eb 37 [2] ed 02 [2] c3 02 [2] fc 1e }

  condition:
    any of them
}