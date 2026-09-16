rule TTP_XOR_WriteProcessMemory_a47f {
  strings:
    $key_a47f = { f3 0d [2] c1 2f [2] c7 1a [2] e9 1a [2] d6 06 }

  condition:
    any of them
}