rule TTP_XOR_WriteProcessMemory_b43a {
  strings:
    $key_b43a = { e3 48 [2] d1 6a [2] d7 5f [2] f9 5f [2] c6 43 }

  condition:
    any of them
}