rule TTP_XOR_WriteProcessMemory_a63f {
  strings:
    $key_a63f = { f1 4d [2] c3 6f [2] c5 5a [2] eb 5a [2] d4 46 }

  condition:
    any of them
}