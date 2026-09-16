rule TTP_XOR_WriteProcessMemory_b16a {
  strings:
    $key_b16a = { e6 18 [2] d4 3a [2] d2 0f [2] fc 0f [2] c3 13 }

  condition:
    any of them
}