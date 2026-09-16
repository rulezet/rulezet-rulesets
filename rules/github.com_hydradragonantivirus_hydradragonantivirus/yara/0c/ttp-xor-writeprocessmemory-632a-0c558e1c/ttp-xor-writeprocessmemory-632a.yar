rule TTP_XOR_WriteProcessMemory_632a {
  strings:
    $key_632a = { 34 58 [2] 06 7a [2] 00 4f [2] 2e 4f [2] 11 53 }

  condition:
    any of them
}