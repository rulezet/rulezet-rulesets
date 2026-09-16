rule TTP_XOR_WriteProcessMemory_1d2a {
  strings:
    $key_1d2a = { 4a 58 [2] 78 7a [2] 7e 4f [2] 50 4f [2] 6f 53 }

  condition:
    any of them
}