rule TTP_XOR_WriteProcessMemory_643f {
  strings:
    $key_643f = { 33 4d [2] 01 6f [2] 07 5a [2] 29 5a [2] 16 46 }

  condition:
    any of them
}