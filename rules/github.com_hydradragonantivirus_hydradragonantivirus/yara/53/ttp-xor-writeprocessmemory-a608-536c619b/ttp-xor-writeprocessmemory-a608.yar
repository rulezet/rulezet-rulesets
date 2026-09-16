rule TTP_XOR_WriteProcessMemory_a608 {
  strings:
    $key_a608 = { f1 7a [2] c3 58 [2] c5 6d [2] eb 6d [2] d4 71 }

  condition:
    any of them
}