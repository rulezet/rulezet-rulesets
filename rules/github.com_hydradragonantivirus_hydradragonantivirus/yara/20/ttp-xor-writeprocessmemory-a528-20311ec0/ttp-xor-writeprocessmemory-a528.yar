rule TTP_XOR_WriteProcessMemory_a528 {
  strings:
    $key_a528 = { f2 5a [2] c0 78 [2] c6 4d [2] e8 4d [2] d7 51 }

  condition:
    any of them
}