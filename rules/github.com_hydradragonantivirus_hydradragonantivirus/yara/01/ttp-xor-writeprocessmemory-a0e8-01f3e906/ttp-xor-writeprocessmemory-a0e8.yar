rule TTP_XOR_WriteProcessMemory_a0e8 {
  strings:
    $key_a0e8 = { f7 9a [2] c5 b8 [2] c3 8d [2] ed 8d [2] d2 91 }

  condition:
    any of them
}