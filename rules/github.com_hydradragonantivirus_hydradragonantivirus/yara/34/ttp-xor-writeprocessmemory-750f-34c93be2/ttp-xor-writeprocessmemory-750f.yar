rule TTP_XOR_WriteProcessMemory_750f {
  strings:
    $key_750f = { 22 7d [2] 10 5f [2] 16 6a [2] 38 6a [2] 07 76 }

  condition:
    any of them
}