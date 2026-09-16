rule TTP_XOR_WriteProcessMemory_5d6f {
  strings:
    $key_5d6f = { 0a 1d [2] 38 3f [2] 3e 0a [2] 10 0a [2] 2f 16 }

  condition:
    any of them
}