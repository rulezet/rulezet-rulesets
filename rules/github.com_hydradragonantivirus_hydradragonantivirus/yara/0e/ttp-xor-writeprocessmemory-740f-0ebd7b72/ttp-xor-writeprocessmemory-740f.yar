rule TTP_XOR_WriteProcessMemory_740f {
  strings:
    $key_740f = { 23 7d [2] 11 5f [2] 17 6a [2] 39 6a [2] 06 76 }

  condition:
    any of them
}