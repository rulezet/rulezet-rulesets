rule TTP_XOR_WriteProcessMemory_a2ff {
  strings:
    $key_a2ff = { f5 8d [2] c7 af [2] c1 9a [2] ef 9a [2] d0 86 }

  condition:
    any of them
}