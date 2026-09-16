rule TTP_XOR_WriteProcessMemory_774a {
  strings:
    $key_774a = { 20 38 [2] 12 1a [2] 14 2f [2] 3a 2f [2] 05 33 }

  condition:
    any of them
}