rule TTP_XOR_WriteProcessMemory_5c6a {
  strings:
    $key_5c6a = { 0b 18 [2] 39 3a [2] 3f 0f [2] 11 0f [2] 2e 13 }

  condition:
    any of them
}