rule TTP_XOR_WriteProcessMemory_a6e8 {
  strings:
    $key_a6e8 = { f1 9a [2] c3 b8 [2] c5 8d [2] eb 8d [2] d4 91 }

  condition:
    any of them
}