rule TTP_XOR_WriteProcessMemory_8ea7 {
  strings:
    $key_8ea7 = { d9 d5 [2] eb f7 [2] ed c2 [2] c3 c2 [2] fc de }

  condition:
    any of them
}