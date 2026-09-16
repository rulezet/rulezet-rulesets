rule TTP_XOR_WriteProcessMemory_b51d {
  strings:
    $key_b51d = { e2 6f [2] d0 4d [2] d6 78 [2] f8 78 [2] c7 64 }

  condition:
    any of them
}