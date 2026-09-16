rule TTP_XOR_WriteProcessMemory_8ea5 {
  strings:
    $key_8ea5 = { d9 d7 [2] eb f5 [2] ed c0 [2] c3 c0 [2] fc dc }

  condition:
    any of them
}