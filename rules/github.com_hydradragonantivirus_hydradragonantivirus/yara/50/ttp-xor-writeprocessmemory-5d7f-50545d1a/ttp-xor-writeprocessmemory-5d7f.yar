rule TTP_XOR_WriteProcessMemory_5d7f {
  strings:
    $key_5d7f = { 0a 0d [2] 38 2f [2] 3e 1a [2] 10 1a [2] 2f 06 }

  condition:
    any of them
}