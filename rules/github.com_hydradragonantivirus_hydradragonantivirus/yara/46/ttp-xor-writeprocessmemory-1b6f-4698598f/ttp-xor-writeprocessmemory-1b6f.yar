rule TTP_XOR_WriteProcessMemory_1b6f {
  strings:
    $key_1b6f = { 4c 1d [2] 7e 3f [2] 78 0a [2] 56 0a [2] 69 16 }

  condition:
    any of them
}