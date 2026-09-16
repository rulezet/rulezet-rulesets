rule TTP_XOR_WriteProcessMemory_a48b {
  strings:
    $key_a48b = { f3 f9 [2] c1 db [2] c7 ee [2] e9 ee [2] d6 f2 }

  condition:
    any of them
}