rule TTP_XOR_WriteProcessMemory_1d7f {
  strings:
    $key_1d7f = { 4a 0d [2] 78 2f [2] 7e 1a [2] 50 1a [2] 6f 06 }

  condition:
    any of them
}