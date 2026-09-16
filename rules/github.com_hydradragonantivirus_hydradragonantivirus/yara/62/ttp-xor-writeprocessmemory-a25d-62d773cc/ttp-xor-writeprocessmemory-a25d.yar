rule TTP_XOR_WriteProcessMemory_a25d {
  strings:
    $key_a25d = { f5 2f [2] c7 0d [2] c1 38 [2] ef 38 [2] d0 24 }

  condition:
    any of them
}