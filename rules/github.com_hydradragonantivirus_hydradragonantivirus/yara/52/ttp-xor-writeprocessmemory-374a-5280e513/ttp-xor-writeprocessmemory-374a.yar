rule TTP_XOR_WriteProcessMemory_374a {
  strings:
    $key_374a = { 60 38 [2] 52 1a [2] 54 2f [2] 7a 2f [2] 45 33 }

  condition:
    any of them
}