rule TTP_XOR_WriteProcessMemory_770f {
  strings:
    $key_770f = { 20 7d [2] 12 5f [2] 14 6a [2] 3a 6a [2] 05 76 }

  condition:
    any of them
}