rule TTP_XOR_WriteProcessMemory_5c2a {
  strings:
    $key_5c2a = { 0b 58 [2] 39 7a [2] 3f 4f [2] 11 4f [2] 2e 53 }

  condition:
    any of them
}