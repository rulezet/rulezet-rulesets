rule TTP_XOR_WriteProcessMemory_276f {
  strings:
    $key_276f = { 70 1d [2] 42 3f [2] 44 0a [2] 6a 0a [2] 55 16 }

  condition:
    any of them
}