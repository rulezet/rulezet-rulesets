rule TTP_XOR_WriteProcessMemory_a07f {
  strings:
    $key_a07f = { f7 0d [2] c5 2f [2] c3 1a [2] ed 1a [2] d2 06 }

  condition:
    any of them
}