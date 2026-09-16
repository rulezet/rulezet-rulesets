rule TTP_XOR_WriteProcessMemory_a753 {
  strings:
    $key_a753 = { f0 21 [2] c2 03 [2] c4 36 [2] ea 36 [2] d5 2a }

  condition:
    any of them
}