rule TTP_XOR_WriteProcessMemory_171a {
  strings:
    $key_171a = { 40 68 [2] 72 4a [2] 74 7f [2] 5a 7f [2] 65 63 }

  condition:
    any of them
}