rule TTP_XOR_WriteProcessMemory_a770 {
  strings:
    $key_a770 = { f0 02 [2] c2 20 [2] c4 15 [2] ea 15 [2] d5 09 }

  condition:
    any of them
}