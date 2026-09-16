rule TTP_XOR_WriteProcessMemory_606f {
  strings:
    $key_606f = { 37 1d [2] 05 3f [2] 03 0a [2] 2d 0a [2] 12 16 }

  condition:
    any of them
}