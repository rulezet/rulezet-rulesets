rule TTP_XOR_WriteProcessMemory_1c7f {
  strings:
    $key_1c7f = { 4b 0d [2] 79 2f [2] 7f 1a [2] 51 1a [2] 6e 06 }

  condition:
    any of them
}