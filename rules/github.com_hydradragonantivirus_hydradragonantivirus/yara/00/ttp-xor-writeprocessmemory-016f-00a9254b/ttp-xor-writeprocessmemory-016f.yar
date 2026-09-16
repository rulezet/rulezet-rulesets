rule TTP_XOR_WriteProcessMemory_016f {
  strings:
    $key_016f = { 56 1d [2] 64 3f [2] 62 0a [2] 4c 0a [2] 73 16 }

  condition:
    any of them
}