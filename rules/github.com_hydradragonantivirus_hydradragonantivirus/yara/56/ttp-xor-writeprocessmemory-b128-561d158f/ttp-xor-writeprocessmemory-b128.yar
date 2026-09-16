rule TTP_XOR_WriteProcessMemory_b128 {
  strings:
    $key_b128 = { e6 5a [2] d4 78 [2] d2 4d [2] fc 4d [2] c3 51 }

  condition:
    any of them
}