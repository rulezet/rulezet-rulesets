rule TTP_XOR_WriteProcessMemory_5c1a {
  strings:
    $key_5c1a = { 0b 68 [2] 39 4a [2] 3f 7f [2] 11 7f [2] 2e 63 }

  condition:
    any of them
}