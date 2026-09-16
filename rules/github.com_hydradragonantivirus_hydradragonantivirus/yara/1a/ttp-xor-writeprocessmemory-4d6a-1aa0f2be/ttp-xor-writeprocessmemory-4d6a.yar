rule TTP_XOR_WriteProcessMemory_4d6a {
  strings:
    $key_4d6a = { 1a 18 [2] 28 3a [2] 2e 0f [2] 00 0f [2] 3f 13 }

  condition:
    any of them
}