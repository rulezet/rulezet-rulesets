rule TTP_XOR_WriteProcessMemory_b56a {
  strings:
    $key_b56a = { e2 18 [2] d0 3a [2] d6 0f [2] f8 0f [2] c7 13 }

  condition:
    any of them
}