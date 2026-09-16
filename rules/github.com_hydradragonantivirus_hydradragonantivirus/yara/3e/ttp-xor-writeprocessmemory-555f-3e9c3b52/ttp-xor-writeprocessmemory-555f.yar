rule TTP_XOR_WriteProcessMemory_555f {
  strings:
    $key_555f = { 02 2d [2] 30 0f [2] 36 3a [2] 18 3a [2] 27 26 }

  condition:
    any of them
}