rule TTP_XOR_WriteProcessMemory_447a {
  strings:
    $key_447a = { 13 08 [2] 21 2a [2] 27 1f [2] 09 1f [2] 36 03 }

  condition:
    any of them
}