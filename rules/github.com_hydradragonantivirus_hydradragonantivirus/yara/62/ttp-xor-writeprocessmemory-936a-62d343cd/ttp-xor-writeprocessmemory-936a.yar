rule TTP_XOR_WriteProcessMemory_936a {
  strings:
    $key_936a = { c4 18 [2] f6 3a [2] f0 0f [2] de 0f [2] e1 13 }

  condition:
    any of them
}