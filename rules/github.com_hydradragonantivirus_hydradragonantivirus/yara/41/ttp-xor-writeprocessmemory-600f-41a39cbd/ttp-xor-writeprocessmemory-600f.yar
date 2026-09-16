rule TTP_XOR_WriteProcessMemory_600f {
  strings:
    $key_600f = { 37 7d [2] 05 5f [2] 03 6a [2] 2d 6a [2] 12 76 }

  condition:
    any of them
}