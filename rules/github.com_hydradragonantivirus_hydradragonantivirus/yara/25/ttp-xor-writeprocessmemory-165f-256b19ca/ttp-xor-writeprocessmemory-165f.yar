rule TTP_XOR_WriteProcessMemory_165f {
  strings:
    $key_165f = { 41 2d [2] 73 0f [2] 75 3a [2] 5b 3a [2] 64 26 }

  condition:
    any of them
}