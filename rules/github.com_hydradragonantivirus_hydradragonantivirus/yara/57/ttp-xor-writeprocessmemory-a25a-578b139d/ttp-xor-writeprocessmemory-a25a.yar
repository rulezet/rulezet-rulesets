rule TTP_XOR_WriteProcessMemory_a25a {
  strings:
    $key_a25a = { f5 28 [2] c7 0a [2] c1 3f [2] ef 3f [2] d0 23 }

  condition:
    any of them
}