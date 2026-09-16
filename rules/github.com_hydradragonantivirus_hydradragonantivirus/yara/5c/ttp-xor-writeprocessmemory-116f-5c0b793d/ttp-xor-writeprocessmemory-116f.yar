rule TTP_XOR_WriteProcessMemory_116f {
  strings:
    $key_116f = { 46 1d [2] 74 3f [2] 72 0a [2] 5c 0a [2] 63 16 }

  condition:
    any of them
}