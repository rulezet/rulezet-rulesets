rule TTP_XOR_WriteProcessMemory_777a {
  strings:
    $key_777a = { 20 08 [2] 12 2a [2] 14 1f [2] 3a 1f [2] 05 03 }

  condition:
    any of them
}