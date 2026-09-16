rule TTP_XOR_WriteProcessMemory_1d2f {
  strings:
    $key_1d2f = { 4a 5d [2] 78 7f [2] 7e 4a [2] 50 4a [2] 6f 56 }

  condition:
    any of them
}