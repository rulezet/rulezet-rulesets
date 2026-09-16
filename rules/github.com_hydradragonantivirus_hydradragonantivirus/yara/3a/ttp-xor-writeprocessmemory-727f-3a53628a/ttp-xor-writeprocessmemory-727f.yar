rule TTP_XOR_WriteProcessMemory_727f {
  strings:
    $key_727f = { 25 0d [2] 17 2f [2] 11 1a [2] 3f 1a [2] 00 06 }

  condition:
    any of them
}