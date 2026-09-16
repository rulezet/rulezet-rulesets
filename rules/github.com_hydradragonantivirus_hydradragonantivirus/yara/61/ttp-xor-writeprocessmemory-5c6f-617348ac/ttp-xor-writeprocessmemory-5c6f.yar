rule TTP_XOR_WriteProcessMemory_5c6f {
  strings:
    $key_5c6f = { 0b 1d [2] 39 3f [2] 3f 0a [2] 11 0a [2] 2e 16 }

  condition:
    any of them
}