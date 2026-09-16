rule TTP_XOR_WriteProcessMemory_434a {
  strings:
    $key_434a = { 14 38 [2] 26 1a [2] 20 2f [2] 0e 2f [2] 31 33 }

  condition:
    any of them
}