rule TTP_XOR_WriteProcessMemory_556f {
  strings:
    $key_556f = { 02 1d [2] 30 3f [2] 36 0a [2] 18 0a [2] 27 16 }

  condition:
    any of them
}