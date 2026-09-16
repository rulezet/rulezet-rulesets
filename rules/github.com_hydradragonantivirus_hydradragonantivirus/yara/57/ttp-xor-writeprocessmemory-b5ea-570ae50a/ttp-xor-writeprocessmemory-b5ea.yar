rule TTP_XOR_WriteProcessMemory_b5ea {
  strings:
    $key_b5ea = { e2 98 [2] d0 ba [2] d6 8f [2] f8 8f [2] c7 93 }

  condition:
    any of them
}