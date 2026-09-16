rule TTP_XOR_WriteProcessMemory_5c5a {
  strings:
    $key_5c5a = { 0b 28 [2] 39 0a [2] 3f 3f [2] 11 3f [2] 2e 23 }

  condition:
    any of them
}