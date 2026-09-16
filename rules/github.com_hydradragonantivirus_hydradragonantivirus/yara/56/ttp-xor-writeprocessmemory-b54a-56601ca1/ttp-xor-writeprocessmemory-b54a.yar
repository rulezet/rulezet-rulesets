rule TTP_XOR_WriteProcessMemory_b54a {
  strings:
    $key_b54a = { e2 38 [2] d0 1a [2] d6 2f [2] f8 2f [2] c7 33 }

  condition:
    any of them
}