rule TTP_XOR_WriteProcessMemory_b4ea {
  strings:
    $key_b4ea = { e3 98 [2] d1 ba [2] d7 8f [2] f9 8f [2] c6 93 }

  condition:
    any of them
}