rule TTP_XOR_WriteProcessMemory_a777 {
  strings:
    $key_a777 = { f0 05 [2] c2 27 [2] c4 12 [2] ea 12 [2] d5 0e }

  condition:
    any of them
}