rule TTP_XOR_WriteProcessMemory_b13f {
  strings:
    $key_b13f = { e6 4d [2] d4 6f [2] d2 5a [2] fc 5a [2] c3 46 }

  condition:
    any of them
}