rule TTP_XOR_WriteProcessMemory_a7ce {
  strings:
    $key_a7ce = { f0 bc [2] c2 9e [2] c4 ab [2] ea ab [2] d5 b7 }

  condition:
    any of them
}