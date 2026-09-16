rule TTP_XOR_WriteProcessMemory_a7f8 {
  strings:
    $key_a7f8 = { f0 8a [2] c2 a8 [2] c4 9d [2] ea 9d [2] d5 81 }

  condition:
    any of them
}