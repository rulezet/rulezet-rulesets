rule TTP_XOR_WriteProcessMemory_a27a {
  strings:
    $key_a27a = { f5 08 [2] c7 2a [2] c1 1f [2] ef 1f [2] d0 03 }

  condition:
    any of them
}