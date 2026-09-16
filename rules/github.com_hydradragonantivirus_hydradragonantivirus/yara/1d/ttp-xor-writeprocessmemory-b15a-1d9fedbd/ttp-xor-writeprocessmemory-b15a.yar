rule TTP_XOR_WriteProcessMemory_b15a {
  strings:
    $key_b15a = { e6 28 [2] d4 0a [2] d2 3f [2] fc 3f [2] c3 23 }

  condition:
    any of them
}