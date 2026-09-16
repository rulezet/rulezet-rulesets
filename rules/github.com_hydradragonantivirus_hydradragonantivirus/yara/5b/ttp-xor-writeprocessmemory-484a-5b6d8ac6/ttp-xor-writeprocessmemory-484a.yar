rule TTP_XOR_WriteProcessMemory_484a {
  strings:
    $key_484a = { 1f 38 [2] 2d 1a [2] 2b 2f [2] 05 2f [2] 3a 33 }

  condition:
    any of them
}