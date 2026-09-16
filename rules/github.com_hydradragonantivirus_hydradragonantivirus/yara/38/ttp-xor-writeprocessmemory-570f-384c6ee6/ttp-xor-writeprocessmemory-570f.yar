rule TTP_XOR_WriteProcessMemory_570f {
  strings:
    $key_570f = { 00 7d [2] 32 5f [2] 34 6a [2] 1a 6a [2] 25 76 }

  condition:
    any of them
}