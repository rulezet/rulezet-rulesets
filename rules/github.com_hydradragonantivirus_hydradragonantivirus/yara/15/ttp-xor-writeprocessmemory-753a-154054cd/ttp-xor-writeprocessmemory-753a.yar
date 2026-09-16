rule TTP_XOR_WriteProcessMemory_753a {
  strings:
    $key_753a = { 22 48 [2] 10 6a [2] 16 5f [2] 38 5f [2] 07 43 }

  condition:
    any of them
}