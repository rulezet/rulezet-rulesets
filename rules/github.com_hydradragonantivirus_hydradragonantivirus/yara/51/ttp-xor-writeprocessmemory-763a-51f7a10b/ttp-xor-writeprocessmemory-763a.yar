rule TTP_XOR_WriteProcessMemory_763a {
  strings:
    $key_763a = { 21 48 [2] 13 6a [2] 15 5f [2] 3b 5f [2] 04 43 }

  condition:
    any of them
}