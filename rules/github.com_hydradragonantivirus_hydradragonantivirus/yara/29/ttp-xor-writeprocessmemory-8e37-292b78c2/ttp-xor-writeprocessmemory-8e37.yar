rule TTP_XOR_WriteProcessMemory_8e37 {
  strings:
    $key_8e37 = { d9 45 [2] eb 67 [2] ed 52 [2] c3 52 [2] fc 4e }

  condition:
    any of them
}