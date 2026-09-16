rule TTP_XOR_WriteProcessMemory_186f {
  strings:
    $key_186f = { 4f 1d [2] 7d 3f [2] 7b 0a [2] 55 0a [2] 6a 16 }

  condition:
    any of them
}