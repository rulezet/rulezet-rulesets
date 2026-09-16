rule TTP_XOR_WriteProcessMemory_560f {
  strings:
    $key_560f = { 01 7d [2] 33 5f [2] 35 6a [2] 1b 6a [2] 24 76 }

  condition:
    any of them
}