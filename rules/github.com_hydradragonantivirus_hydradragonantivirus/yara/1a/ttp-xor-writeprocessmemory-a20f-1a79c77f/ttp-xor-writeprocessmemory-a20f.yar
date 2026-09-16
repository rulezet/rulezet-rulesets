rule TTP_XOR_WriteProcessMemory_a20f {
  strings:
    $key_a20f = { f5 7d [2] c7 5f [2] c1 6a [2] ef 6a [2] d0 76 }

  condition:
    any of them
}