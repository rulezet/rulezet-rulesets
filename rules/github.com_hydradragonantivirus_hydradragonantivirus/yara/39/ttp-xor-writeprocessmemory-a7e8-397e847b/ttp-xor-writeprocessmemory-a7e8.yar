rule TTP_XOR_WriteProcessMemory_a7e8 {
  strings:
    $key_a7e8 = { f0 9a [2] c2 b8 [2] c4 8d [2] ea 8d [2] d5 91 }

  condition:
    any of them
}