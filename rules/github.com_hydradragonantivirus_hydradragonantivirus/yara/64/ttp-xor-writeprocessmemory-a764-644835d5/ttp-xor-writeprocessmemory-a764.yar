rule TTP_XOR_WriteProcessMemory_a764 {
  strings:
    $key_a764 = { f0 16 [2] c2 34 [2] c4 01 [2] ea 01 [2] d5 1d }

  condition:
    any of them
}