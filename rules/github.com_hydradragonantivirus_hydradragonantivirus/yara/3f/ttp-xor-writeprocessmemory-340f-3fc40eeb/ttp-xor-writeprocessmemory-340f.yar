rule TTP_XOR_WriteProcessMemory_340f {
  strings:
    $key_340f = { 63 7d [2] 51 5f [2] 57 6a [2] 79 6a [2] 46 76 }

  condition:
    any of them
}