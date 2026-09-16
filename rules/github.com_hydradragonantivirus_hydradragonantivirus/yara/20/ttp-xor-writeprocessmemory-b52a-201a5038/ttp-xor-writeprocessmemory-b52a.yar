rule TTP_XOR_WriteProcessMemory_b52a {
  strings:
    $key_b52a = { e2 58 [2] d0 7a [2] d6 4f [2] f8 4f [2] c7 53 }

  condition:
    any of them
}