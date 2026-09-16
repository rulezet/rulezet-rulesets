rule TTP_XOR_WriteProcessMemory_577f {
  strings:
    $key_577f = { 00 0d [2] 32 2f [2] 34 1a [2] 1a 1a [2] 25 06 }

  condition:
    any of them
}