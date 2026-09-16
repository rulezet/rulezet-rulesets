rule TTP_XOR_WriteProcessMemory_466f {
  strings:
    $key_466f = { 11 1d [2] 23 3f [2] 25 0a [2] 0b 0a [2] 34 16 }

  condition:
    any of them
}