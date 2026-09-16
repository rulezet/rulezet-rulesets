rule TTP_XOR_WriteProcessMemory_777f {
  strings:
    $key_777f = { 20 0d [2] 12 2f [2] 14 1a [2] 3a 1a [2] 05 06 }

  condition:
    any of them
}