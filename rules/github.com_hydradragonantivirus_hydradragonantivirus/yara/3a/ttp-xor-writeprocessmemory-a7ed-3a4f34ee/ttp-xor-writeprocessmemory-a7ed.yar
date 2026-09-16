rule TTP_XOR_WriteProcessMemory_a7ed {
  strings:
    $key_a7ed = { f0 9f [2] c2 bd [2] c4 88 [2] ea 88 [2] d5 94 }

  condition:
    any of them
}