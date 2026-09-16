rule TTP_XOR_WriteProcessMemory_b42a {
  strings:
    $key_b42a = { e3 58 [2] d1 7a [2] d7 4f [2] f9 4f [2] c6 53 }

  condition:
    any of them
}