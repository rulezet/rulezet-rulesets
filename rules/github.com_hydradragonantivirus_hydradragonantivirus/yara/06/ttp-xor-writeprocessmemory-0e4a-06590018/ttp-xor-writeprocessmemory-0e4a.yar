rule TTP_XOR_WriteProcessMemory_0e4a {
  strings:
    $key_0e4a = { 59 38 [2] 6b 1a [2] 6d 2f [2] 43 2f [2] 7c 33 }

  condition:
    any of them
}