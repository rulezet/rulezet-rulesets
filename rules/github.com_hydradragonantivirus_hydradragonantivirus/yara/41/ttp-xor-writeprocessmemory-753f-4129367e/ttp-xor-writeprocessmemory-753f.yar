rule TTP_XOR_WriteProcessMemory_753f {
  strings:
    $key_753f = { 22 4d [2] 10 6f [2] 16 5a [2] 38 5a [2] 07 46 }

  condition:
    any of them
}