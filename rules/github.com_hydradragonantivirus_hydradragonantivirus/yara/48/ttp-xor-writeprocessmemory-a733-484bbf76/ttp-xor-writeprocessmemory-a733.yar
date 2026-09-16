rule TTP_XOR_WriteProcessMemory_a733 {
  strings:
    $key_a733 = { f0 41 [2] c2 63 [2] c4 56 [2] ea 56 [2] d5 4a }

  condition:
    any of them
}