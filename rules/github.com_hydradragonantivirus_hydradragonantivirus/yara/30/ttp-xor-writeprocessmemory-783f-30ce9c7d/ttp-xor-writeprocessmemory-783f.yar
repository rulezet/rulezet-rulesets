rule TTP_XOR_WriteProcessMemory_783f {
  strings:
    $key_783f = { 2f 4d [2] 1d 6f [2] 1b 5a [2] 35 5a [2] 0a 46 }

  condition:
    any of them
}