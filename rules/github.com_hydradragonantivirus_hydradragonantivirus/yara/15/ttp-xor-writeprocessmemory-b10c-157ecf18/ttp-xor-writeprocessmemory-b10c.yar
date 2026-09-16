rule TTP_XOR_WriteProcessMemory_b10c {
  strings:
    $key_b10c = { e6 7e [2] d4 5c [2] d2 69 [2] fc 69 [2] c3 75 }

  condition:
    any of them
}