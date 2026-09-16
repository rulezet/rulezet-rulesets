rule TTP_XOR_WriteProcessMemory_8ea6 {
  strings:
    $key_8ea6 = { d9 d4 [2] eb f6 [2] ed c3 [2] c3 c3 [2] fc df }

  condition:
    any of them
}