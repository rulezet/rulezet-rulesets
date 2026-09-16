rule TTP_XOR_WriteProcessMemory_8ea3 {
  strings:
    $key_8ea3 = { d9 d1 [2] eb f3 [2] ed c6 [2] c3 c6 [2] fc da }

  condition:
    any of them
}