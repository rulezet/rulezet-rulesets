rule TTP_XOR_WriteProcessMemory_6f2f {
  strings:
    $key_6f2f = { 38 5d [2] 0a 7f [2] 0c 4a [2] 22 4a [2] 1d 56 }

  condition:
    any of them
}