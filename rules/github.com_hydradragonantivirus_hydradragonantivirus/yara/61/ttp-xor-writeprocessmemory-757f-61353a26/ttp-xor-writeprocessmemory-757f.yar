rule TTP_XOR_WriteProcessMemory_757f {
  strings:
    $key_757f = { 22 0d [2] 10 2f [2] 16 1a [2] 38 1a [2] 07 06 }

  condition:
    any of them
}