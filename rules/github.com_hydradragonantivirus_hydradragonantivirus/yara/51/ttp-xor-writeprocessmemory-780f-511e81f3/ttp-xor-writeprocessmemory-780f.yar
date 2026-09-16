rule TTP_XOR_WriteProcessMemory_780f {
  strings:
    $key_780f = { 2f 7d [2] 1d 5f [2] 1b 6a [2] 35 6a [2] 0a 76 }

  condition:
    any of them
}