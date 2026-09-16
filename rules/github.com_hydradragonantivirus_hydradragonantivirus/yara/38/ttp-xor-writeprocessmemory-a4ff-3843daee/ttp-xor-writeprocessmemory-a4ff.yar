rule TTP_XOR_WriteProcessMemory_a4ff {
  strings:
    $key_a4ff = { f3 8d [2] c1 af [2] c7 9a [2] e9 9a [2] d6 86 }

  condition:
    any of them
}