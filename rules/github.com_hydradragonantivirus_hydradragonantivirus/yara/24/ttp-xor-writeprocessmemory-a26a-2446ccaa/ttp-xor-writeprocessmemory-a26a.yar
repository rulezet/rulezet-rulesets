rule TTP_XOR_WriteProcessMemory_a26a {
  strings:
    $key_a26a = { f5 18 [2] c7 3a [2] c1 0f [2] ef 0f [2] d0 13 }

  condition:
    any of them
}