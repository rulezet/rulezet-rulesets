rule TTP_XOR_WriteProcessMemory_a2ca {
  strings:
    $key_a2ca = { f5 b8 [2] c7 9a [2] c1 af [2] ef af [2] d0 b3 }

  condition:
    any of them
}