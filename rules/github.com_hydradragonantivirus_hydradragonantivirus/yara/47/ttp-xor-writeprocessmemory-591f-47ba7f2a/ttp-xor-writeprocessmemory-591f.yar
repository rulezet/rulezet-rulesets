rule TTP_XOR_WriteProcessMemory_591f {
  strings:
    $key_591f = { 0e 6d [2] 3c 4f [2] 3a 7a [2] 14 7a [2] 2b 66 }

  condition:
    any of them
}