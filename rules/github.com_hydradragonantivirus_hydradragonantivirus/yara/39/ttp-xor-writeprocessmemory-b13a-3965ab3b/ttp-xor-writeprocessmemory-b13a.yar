rule TTP_XOR_WriteProcessMemory_b13a {
  strings:
    $key_b13a = { e6 48 [2] d4 6a [2] d2 5f [2] fc 5f [2] c3 43 }

  condition:
    any of them
}