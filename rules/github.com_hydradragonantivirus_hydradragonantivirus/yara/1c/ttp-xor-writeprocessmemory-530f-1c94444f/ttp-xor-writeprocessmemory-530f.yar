rule TTP_XOR_WriteProcessMemory_530f {
  strings:
    $key_530f = { 04 7d [2] 36 5f [2] 30 6a [2] 1e 6a [2] 21 76 }

  condition:
    any of them
}