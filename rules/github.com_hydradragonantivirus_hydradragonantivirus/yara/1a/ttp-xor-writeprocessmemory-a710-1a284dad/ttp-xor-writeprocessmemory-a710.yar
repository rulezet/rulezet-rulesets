rule TTP_XOR_WriteProcessMemory_a710 {
  strings:
    $key_a710 = { f0 62 [2] c2 40 [2] c4 75 [2] ea 75 [2] d5 69 }

  condition:
    any of them
}