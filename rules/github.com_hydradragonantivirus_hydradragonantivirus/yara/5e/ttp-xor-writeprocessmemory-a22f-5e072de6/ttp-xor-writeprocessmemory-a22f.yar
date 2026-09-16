rule TTP_XOR_WriteProcessMemory_a22f {
  strings:
    $key_a22f = { f5 5d [2] c7 7f [2] c1 4a [2] ef 4a [2] d0 56 }

  condition:
    any of them
}