rule TTP_XOR_WriteProcessMemory_b7ea {
  strings:
    $key_b7ea = { e0 98 [2] d2 ba [2] d4 8f [2] fa 8f [2] c5 93 }

  condition:
    any of them
}