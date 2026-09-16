rule TTP_XOR_WriteProcessMemory_404a {
  strings:
    $key_404a = { 17 38 [2] 25 1a [2] 23 2f [2] 0d 2f [2] 32 33 }

  condition:
    any of them
}