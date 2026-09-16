rule TTP_XOR_WriteProcessMemory_a76f {
  strings:
    $key_a76f = { f0 1d [2] c2 3f [2] c4 0a [2] ea 0a [2] d5 16 }

  condition:
    any of them
}