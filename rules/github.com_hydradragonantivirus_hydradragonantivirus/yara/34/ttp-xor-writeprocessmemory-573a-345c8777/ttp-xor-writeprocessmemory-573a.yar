rule TTP_XOR_WriteProcessMemory_573a {
  strings:
    $key_573a = { 00 48 [2] 32 6a [2] 34 5f [2] 1a 5f [2] 25 43 }

  condition:
    any of them
}