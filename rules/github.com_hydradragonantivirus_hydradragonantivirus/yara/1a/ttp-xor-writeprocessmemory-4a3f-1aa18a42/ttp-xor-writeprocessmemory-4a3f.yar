rule TTP_XOR_WriteProcessMemory_4a3f {
  strings:
    $key_4a3f = { 1d 4d [2] 2f 6f [2] 29 5a [2] 07 5a [2] 38 46 }

  condition:
    any of them
}