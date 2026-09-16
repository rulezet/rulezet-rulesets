rule TTP_XOR_WriteProcessMemory_5c3a {
  strings:
    $key_5c3a = { 0b 48 [2] 39 6a [2] 3f 5f [2] 11 5f [2] 2e 43 }

  condition:
    any of them
}