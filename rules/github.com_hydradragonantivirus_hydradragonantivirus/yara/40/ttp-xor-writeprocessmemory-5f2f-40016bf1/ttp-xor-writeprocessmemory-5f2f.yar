rule TTP_XOR_WriteProcessMemory_5f2f {
  strings:
    $key_5f2f = { 08 5d [2] 3a 7f [2] 3c 4a [2] 12 4a [2] 2d 56 }

  condition:
    any of them
}