rule TTP_XOR_WriteProcessMemory_676f {
  strings:
    $key_676f = { 30 1d [2] 02 3f [2] 04 0a [2] 2a 0a [2] 15 16 }

  condition:
    any of them
}