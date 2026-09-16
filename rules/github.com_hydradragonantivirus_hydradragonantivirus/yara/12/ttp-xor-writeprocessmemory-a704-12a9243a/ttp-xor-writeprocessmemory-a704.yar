rule TTP_XOR_WriteProcessMemory_a704 {
  strings:
    $key_a704 = { f0 76 [2] c2 54 [2] c4 61 [2] ea 61 [2] d5 7d }

  condition:
    any of them
}