rule TTP_XOR_WriteProcessMemory_5d4a {
  strings:
    $key_5d4a = { 0a 38 [2] 38 1a [2] 3e 2f [2] 10 2f [2] 2f 33 }

  condition:
    any of them
}