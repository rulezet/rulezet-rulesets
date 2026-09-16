rule TTP_XOR_WriteProcessMemory_a75f {
  strings:
    $key_a75f = { f0 2d [2] c2 0f [2] c4 3a [2] ea 3a [2] d5 26 }

  condition:
    any of them
}