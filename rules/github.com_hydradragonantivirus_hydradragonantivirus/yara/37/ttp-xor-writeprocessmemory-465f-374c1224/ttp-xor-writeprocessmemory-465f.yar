rule TTP_XOR_WriteProcessMemory_465f {
  strings:
    $key_465f = { 11 2d [2] 23 0f [2] 25 3a [2] 0b 3a [2] 34 26 }

  condition:
    any of them
}