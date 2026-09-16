rule TTP_XOR_WriteProcessMemory_a66f {
  strings:
    $key_a66f = { f1 1d [2] c3 3f [2] c5 0a [2] eb 0a [2] d4 16 }

  condition:
    any of them
}