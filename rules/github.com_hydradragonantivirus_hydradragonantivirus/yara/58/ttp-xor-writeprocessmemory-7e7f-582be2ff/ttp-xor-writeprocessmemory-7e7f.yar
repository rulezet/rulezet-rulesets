rule TTP_XOR_WriteProcessMemory_7e7f {
  strings:
    $key_7e7f = { 29 0d [2] 1b 2f [2] 1d 1a [2] 33 1a [2] 0c 06 }

  condition:
    any of them
}