rule TTP_XOR_WriteProcessMemory_636a {
  strings:
    $key_636a = { 34 18 [2] 06 3a [2] 00 0f [2] 2e 0f [2] 11 13 }

  condition:
    any of them
}