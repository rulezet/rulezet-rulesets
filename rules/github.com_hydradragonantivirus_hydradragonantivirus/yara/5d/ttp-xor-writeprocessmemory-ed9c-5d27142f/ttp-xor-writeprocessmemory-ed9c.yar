rule TTP_XOR_WriteProcessMemory_ed9c {
  strings:
    $key_ed9c = { ba ee [2] 88 cc [2] 8e f9 [2] a0 f9 [2] 9f e5 }

  condition:
    any of them
}