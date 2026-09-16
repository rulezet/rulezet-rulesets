rule TTP_XOR_WriteProcessMemory_1c6f {
  strings:
    $key_1c6f = { 4b 1d [2] 79 3f [2] 7f 0a [2] 51 0a [2] 6e 16 }

  condition:
    any of them
}