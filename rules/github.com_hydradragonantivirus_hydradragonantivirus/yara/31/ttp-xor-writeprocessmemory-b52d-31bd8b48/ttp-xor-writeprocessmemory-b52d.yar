rule TTP_XOR_WriteProcessMemory_b52d {
  strings:
    $key_b52d = { e2 5f [2] d0 7d [2] d6 48 [2] f8 48 [2] c7 54 }

  condition:
    any of them
}