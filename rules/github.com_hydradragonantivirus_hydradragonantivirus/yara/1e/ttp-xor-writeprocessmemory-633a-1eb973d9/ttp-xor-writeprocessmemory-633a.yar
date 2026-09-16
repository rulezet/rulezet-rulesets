rule TTP_XOR_WriteProcessMemory_633a {
  strings:
    $key_633a = { 34 48 [2] 06 6a [2] 00 5f [2] 2e 5f [2] 11 43 }

  condition:
    any of them
}