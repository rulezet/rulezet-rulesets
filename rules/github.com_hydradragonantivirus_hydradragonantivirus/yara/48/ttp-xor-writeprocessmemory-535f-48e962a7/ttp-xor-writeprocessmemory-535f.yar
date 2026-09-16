rule TTP_XOR_WriteProcessMemory_535f {
  strings:
    $key_535f = { 04 2d [2] 36 0f [2] 30 3a [2] 1e 3a [2] 21 26 }

  condition:
    any of them
}