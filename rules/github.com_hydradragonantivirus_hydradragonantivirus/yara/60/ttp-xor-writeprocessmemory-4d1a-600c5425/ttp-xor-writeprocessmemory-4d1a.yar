rule TTP_XOR_WriteProcessMemory_4d1a {
  strings:
    $key_4d1a = { 1a 68 [2] 28 4a [2] 2e 7f [2] 00 7f [2] 3f 63 }

  condition:
    any of them
}