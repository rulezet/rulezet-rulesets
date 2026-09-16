rule TTP_XOR_WriteProcessMemory_4a7f {
  strings:
    $key_4a7f = { 1d 0d [2] 2f 2f [2] 29 1a [2] 07 1a [2] 38 06 }

  condition:
    any of them
}