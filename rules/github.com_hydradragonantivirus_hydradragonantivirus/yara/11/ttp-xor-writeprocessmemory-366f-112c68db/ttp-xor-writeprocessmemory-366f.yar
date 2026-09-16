rule TTP_XOR_WriteProcessMemory_366f {
  strings:
    $key_366f = { 61 1d [2] 53 3f [2] 55 0a [2] 7b 0a [2] 44 16 }

  condition:
    any of them
}