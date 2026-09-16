rule TTP_XOR_WriteProcessMemory_575a {
  strings:
    $key_575a = { 00 28 [2] 32 0a [2] 34 3f [2] 1a 3f [2] 25 23 }

  condition:
    any of them
}