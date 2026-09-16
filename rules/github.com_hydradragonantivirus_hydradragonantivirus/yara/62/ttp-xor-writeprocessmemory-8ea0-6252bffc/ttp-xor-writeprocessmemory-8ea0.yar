rule TTP_XOR_WriteProcessMemory_8ea0 {
  strings:
    $key_8ea0 = { d9 d2 [2] eb f0 [2] ed c5 [2] c3 c5 [2] fc d9 }

  condition:
    any of them
}