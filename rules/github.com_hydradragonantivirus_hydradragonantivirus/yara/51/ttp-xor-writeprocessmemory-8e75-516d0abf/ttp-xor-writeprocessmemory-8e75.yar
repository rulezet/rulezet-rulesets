rule TTP_XOR_WriteProcessMemory_8e75 {
  strings:
    $key_8e75 = { d9 07 [2] eb 25 [2] ed 10 [2] c3 10 [2] fc 0c }

  condition:
    any of them
}