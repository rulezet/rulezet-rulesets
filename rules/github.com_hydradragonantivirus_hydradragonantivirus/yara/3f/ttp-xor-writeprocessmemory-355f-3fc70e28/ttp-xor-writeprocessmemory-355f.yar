rule TTP_XOR_WriteProcessMemory_355f {
  strings:
    $key_355f = { 62 2d [2] 50 0f [2] 56 3a [2] 78 3a [2] 47 26 }

  condition:
    any of them
}