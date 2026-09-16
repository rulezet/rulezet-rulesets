rule TTP_XOR_WriteProcessMemory_6f7f {
  strings:
    $key_6f7f = { 38 0d [2] 0a 2f [2] 0c 1a [2] 22 1a [2] 1d 06 }

  condition:
    any of them
}