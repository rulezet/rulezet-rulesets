rule TTP_XOR_WriteProcessMemory_a741 {
  strings:
    $key_a741 = { f0 33 [2] c2 11 [2] c4 24 [2] ea 24 [2] d5 38 }

  condition:
    any of them
}