rule TTP_XOR_WriteProcessMemory_b1ea {
  strings:
    $key_b1ea = { e6 98 [2] d4 ba [2] d2 8f [2] fc 8f [2] c3 93 }

  condition:
    any of them
}