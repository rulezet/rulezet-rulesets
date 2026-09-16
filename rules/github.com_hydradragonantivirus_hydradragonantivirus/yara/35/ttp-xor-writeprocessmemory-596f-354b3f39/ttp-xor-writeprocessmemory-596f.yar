rule TTP_XOR_WriteProcessMemory_596f {
  strings:
    $key_596f = { 0e 1d [2] 3c 3f [2] 3a 0a [2] 14 0a [2] 2b 16 }

  condition:
    any of them
}