rule TTP_XOR_WriteProcessMemory_b10f {
  strings:
    $key_b10f = { e6 7d [2] d4 5f [2] d2 6a [2] fc 6a [2] c3 76 }

  condition:
    any of them
}