rule TTP_XOR_WriteProcessMemory_a0ff {
  strings:
    $key_a0ff = { f7 8d [2] c5 af [2] c3 9a [2] ed 9a [2] d2 86 }

  condition:
    any of them
}