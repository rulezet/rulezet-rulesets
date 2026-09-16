rule TTP_XOR_WriteProcessMemory_b57f {
  strings:
    $key_b57f = { e2 0d [2] d0 2f [2] d6 1a [2] f8 1a [2] c7 06 }

  condition:
    any of them
}