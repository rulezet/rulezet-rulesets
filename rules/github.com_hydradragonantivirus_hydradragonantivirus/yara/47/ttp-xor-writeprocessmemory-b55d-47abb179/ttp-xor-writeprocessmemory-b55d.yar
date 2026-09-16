rule TTP_XOR_WriteProcessMemory_b55d {
  strings:
    $key_b55d = { e2 2f [2] d0 0d [2] d6 38 [2] f8 38 [2] c7 24 }

  condition:
    any of them
}