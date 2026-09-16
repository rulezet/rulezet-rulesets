rule TTP_XOR_WriteProcessMemory_225f {
  strings:
    $key_225f = { 75 2d [2] 47 0f [2] 41 3a [2] 6f 3a [2] 50 26 }

  condition:
    any of them
}