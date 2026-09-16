rule TTP_XOR_WriteProcessMemory_6f3f {
  strings:
    $key_6f3f = { 38 4d [2] 0a 6f [2] 0c 5a [2] 22 5a [2] 1d 46 }

  condition:
    any of them
}