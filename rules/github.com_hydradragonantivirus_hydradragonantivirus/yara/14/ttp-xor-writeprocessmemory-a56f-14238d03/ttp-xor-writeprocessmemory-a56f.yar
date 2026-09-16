rule TTP_XOR_WriteProcessMemory_a56f {
  strings:
    $key_a56f = { f2 1d [2] c0 3f [2] c6 0a [2] e8 0a [2] d7 16 }

  condition:
    any of them
}