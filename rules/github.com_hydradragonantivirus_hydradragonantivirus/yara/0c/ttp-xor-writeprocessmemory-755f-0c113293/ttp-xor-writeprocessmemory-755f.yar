rule TTP_XOR_WriteProcessMemory_755f {
  strings:
    $key_755f = { 22 2d [2] 10 0f [2] 16 3a [2] 38 3a [2] 07 26 }

  condition:
    any of them
}