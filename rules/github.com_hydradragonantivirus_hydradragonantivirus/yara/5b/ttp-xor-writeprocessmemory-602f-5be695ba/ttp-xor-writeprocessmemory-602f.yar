rule TTP_XOR_WriteProcessMemory_602f {
  strings:
    $key_602f = { 37 5d [2] 05 7f [2] 03 4a [2] 2d 4a [2] 12 56 }

  condition:
    any of them
}