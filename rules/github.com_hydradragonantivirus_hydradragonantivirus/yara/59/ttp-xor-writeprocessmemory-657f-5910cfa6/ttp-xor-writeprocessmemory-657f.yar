rule TTP_XOR_WriteProcessMemory_657f {
  strings:
    $key_657f = { 32 0d [2] 00 2f [2] 06 1a [2] 28 1a [2] 17 06 }

  condition:
    any of them
}