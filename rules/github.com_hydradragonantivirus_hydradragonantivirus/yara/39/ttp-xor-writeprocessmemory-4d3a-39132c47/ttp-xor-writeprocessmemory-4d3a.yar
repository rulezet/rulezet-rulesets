rule TTP_XOR_WriteProcessMemory_4d3a {
  strings:
    $key_4d3a = { 1a 48 [2] 28 6a [2] 2e 5f [2] 00 5f [2] 3f 43 }

  condition:
    any of them
}