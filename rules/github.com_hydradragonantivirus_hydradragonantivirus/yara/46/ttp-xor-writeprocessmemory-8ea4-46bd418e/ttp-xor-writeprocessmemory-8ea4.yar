rule TTP_XOR_WriteProcessMemory_8ea4 {
  strings:
    $key_8ea4 = { d9 d6 [2] eb f4 [2] ed c1 [2] c3 c1 [2] fc dd }

  condition:
    any of them
}