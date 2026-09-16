rule TTP_XOR_WriteProcessMemory_4d4a {
  strings:
    $key_4d4a = { 1a 38 [2] 28 1a [2] 2e 2f [2] 00 2f [2] 3f 33 }

  condition:
    any of them
}