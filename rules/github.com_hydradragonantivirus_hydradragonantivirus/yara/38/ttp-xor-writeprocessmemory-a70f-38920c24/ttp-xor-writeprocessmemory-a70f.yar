rule TTP_XOR_WriteProcessMemory_a70f {
  strings:
    $key_a70f = { f0 7d [2] c2 5f [2] c4 6a [2] ea 6a [2] d5 76 }

  condition:
    any of them
}