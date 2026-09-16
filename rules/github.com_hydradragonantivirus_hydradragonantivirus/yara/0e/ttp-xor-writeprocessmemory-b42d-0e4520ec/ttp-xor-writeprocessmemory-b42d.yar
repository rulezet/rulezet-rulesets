rule TTP_XOR_WriteProcessMemory_b42d {
  strings:
    $key_b42d = { e3 5f [2] d1 7d [2] d7 48 [2] f9 48 [2] c6 54 }

  condition:
    any of them
}