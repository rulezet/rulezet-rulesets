rule TTP_XOR_WriteProcessMemory_755a {
  strings:
    $key_755a = { 22 28 [2] 10 0a [2] 16 3f [2] 38 3f [2] 07 23 }

  condition:
    any of them
}