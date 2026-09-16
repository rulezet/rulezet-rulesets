rule TTP_XOR_WriteProcessMemory_b53d {
  strings:
    $key_b53d = { e2 4f [2] d0 6d [2] d6 58 [2] f8 58 [2] c7 44 }

  condition:
    any of them
}