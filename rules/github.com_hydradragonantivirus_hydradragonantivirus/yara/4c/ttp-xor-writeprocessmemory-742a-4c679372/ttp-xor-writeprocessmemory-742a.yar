rule TTP_XOR_WriteProcessMemory_742a {
  strings:
    $key_742a = { 23 58 [2] 11 7a [2] 17 4f [2] 39 4f [2] 06 53 }

  condition:
    any of them
}