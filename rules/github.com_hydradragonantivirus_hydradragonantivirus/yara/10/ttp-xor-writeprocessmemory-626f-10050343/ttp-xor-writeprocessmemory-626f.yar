rule TTP_XOR_WriteProcessMemory_626f {
  strings:
    $key_626f = { 35 1d [2] 07 3f [2] 01 0a [2] 2f 0a [2] 10 16 }

  condition:
    any of them
}