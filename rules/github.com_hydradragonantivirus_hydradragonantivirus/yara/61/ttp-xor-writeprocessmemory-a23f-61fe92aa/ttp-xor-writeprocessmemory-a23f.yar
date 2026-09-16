rule TTP_XOR_WriteProcessMemory_a23f {
  strings:
    $key_a23f = { f5 4d [2] c7 6f [2] c1 5a [2] ef 5a [2] d0 46 }

  condition:
    any of them
}