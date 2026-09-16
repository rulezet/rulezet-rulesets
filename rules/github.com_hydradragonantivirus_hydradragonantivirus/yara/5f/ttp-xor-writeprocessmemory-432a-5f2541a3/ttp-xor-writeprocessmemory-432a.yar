rule TTP_XOR_WriteProcessMemory_432a {
  strings:
    $key_432a = { 14 58 [2] 26 7a [2] 20 4f [2] 0e 4f [2] 31 53 }

  condition:
    any of them
}