rule TTP_XOR_WriteProcessMemory_b10d {
  strings:
    $key_b10d = { e6 7f [2] d4 5d [2] d2 68 [2] fc 68 [2] c3 74 }

  condition:
    any of them
}