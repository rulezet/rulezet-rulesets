rule TTP_XOR_WriteProcessMemory_a64a {
  strings:
    $key_a64a = { f1 38 [2] c3 1a [2] c5 2f [2] eb 2f [2] d4 33 }

  condition:
    any of them
}