rule TTP_XOR_WriteProcessMemory_a5e8 {
  strings:
    $key_a5e8 = { f2 9a [2] c0 b8 [2] c6 8d [2] e8 8d [2] d7 91 }

  condition:
    any of them
}