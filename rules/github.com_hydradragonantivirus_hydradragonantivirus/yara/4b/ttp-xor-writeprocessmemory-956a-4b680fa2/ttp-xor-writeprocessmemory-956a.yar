rule TTP_XOR_WriteProcessMemory_956a {
  strings:
    $key_956a = { c2 18 [2] f0 3a [2] f6 0f [2] d8 0f [2] e7 13 }

  condition:
    any of them
}