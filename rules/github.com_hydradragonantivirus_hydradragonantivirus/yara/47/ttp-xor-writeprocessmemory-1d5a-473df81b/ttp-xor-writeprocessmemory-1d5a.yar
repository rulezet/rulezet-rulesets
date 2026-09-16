rule TTP_XOR_WriteProcessMemory_1d5a {
  strings:
    $key_1d5a = { 4a 28 [2] 78 0a [2] 7e 3f [2] 50 3f [2] 6f 23 }

  condition:
    any of them
}