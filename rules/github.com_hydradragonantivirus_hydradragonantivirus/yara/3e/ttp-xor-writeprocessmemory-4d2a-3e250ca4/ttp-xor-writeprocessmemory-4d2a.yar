rule TTP_XOR_WriteProcessMemory_4d2a {
  strings:
    $key_4d2a = { 1a 58 [2] 28 7a [2] 2e 4f [2] 00 4f [2] 3f 53 }

  condition:
    any of them
}