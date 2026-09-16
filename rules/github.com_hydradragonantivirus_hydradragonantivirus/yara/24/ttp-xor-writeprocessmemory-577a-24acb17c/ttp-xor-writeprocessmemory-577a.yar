rule TTP_XOR_WriteProcessMemory_577a {
  strings:
    $key_577a = { 00 08 [2] 32 2a [2] 34 1f [2] 1a 1f [2] 25 03 }

  condition:
    any of them
}