rule TTP_XOR_WriteProcessMemory_b57a {
  strings:
    $key_b57a = { e2 08 [2] d0 2a [2] d6 1f [2] f8 1f [2] c7 03 }

  condition:
    any of them
}