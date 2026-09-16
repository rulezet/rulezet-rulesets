rule TTP_XOR_WriteProcessMemory_a77f {
  strings:
    $key_a77f = { f0 0d [2] c2 2f [2] c4 1a [2] ea 1a [2] d5 06 }

  condition:
    any of them
}