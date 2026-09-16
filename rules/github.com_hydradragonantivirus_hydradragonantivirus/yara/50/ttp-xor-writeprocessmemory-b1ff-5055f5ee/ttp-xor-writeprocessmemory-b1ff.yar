rule TTP_XOR_WriteProcessMemory_b1ff {
  strings:
    $key_b1ff = { e6 8d [2] d4 af [2] d2 9a [2] fc 9a [2] c3 86 }

  condition:
    any of them
}