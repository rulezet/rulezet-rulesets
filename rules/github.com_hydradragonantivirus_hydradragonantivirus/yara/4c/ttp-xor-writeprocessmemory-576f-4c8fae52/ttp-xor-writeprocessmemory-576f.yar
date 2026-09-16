rule TTP_XOR_WriteProcessMemory_576f {
  strings:
    $key_576f = { 00 1d [2] 32 3f [2] 34 0a [2] 1a 0a [2] 25 16 }

  condition:
    any of them
}