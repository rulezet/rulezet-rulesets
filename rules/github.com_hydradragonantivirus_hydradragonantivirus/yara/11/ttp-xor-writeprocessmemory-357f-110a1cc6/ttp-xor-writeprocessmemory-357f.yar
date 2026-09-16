rule TTP_XOR_WriteProcessMemory_357f {
  strings:
    $key_357f = { 62 0d [2] 50 2f [2] 56 1a [2] 78 1a [2] 47 06 }

  condition:
    any of them
}