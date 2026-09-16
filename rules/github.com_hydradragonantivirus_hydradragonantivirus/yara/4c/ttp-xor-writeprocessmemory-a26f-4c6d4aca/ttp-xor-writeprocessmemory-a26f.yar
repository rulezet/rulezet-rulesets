rule TTP_XOR_WriteProcessMemory_a26f {
  strings:
    $key_a26f = { f5 1d [2] c7 3f [2] c1 0a [2] ef 0a [2] d0 16 }

  condition:
    any of them
}