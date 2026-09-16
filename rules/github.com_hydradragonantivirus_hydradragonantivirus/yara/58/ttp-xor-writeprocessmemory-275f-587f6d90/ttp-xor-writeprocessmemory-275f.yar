rule TTP_XOR_WriteProcessMemory_275f {
  strings:
    $key_275f = { 70 2d [2] 42 0f [2] 44 3a [2] 6a 3a [2] 55 26 }

  condition:
    any of them
}