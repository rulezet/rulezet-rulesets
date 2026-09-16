rule TTP_XOR_WriteProcessMemory_b41d {
  strings:
    $key_b41d = { e3 6f [2] d1 4d [2] d7 78 [2] f9 78 [2] c6 64 }

  condition:
    any of them
}