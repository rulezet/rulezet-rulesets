rule TTP_XOR_WriteProcessMemory_742f {
  strings:
    $key_742f = { 23 5d [2] 11 7f [2] 17 4a [2] 39 4a [2] 06 56 }

  condition:
    any of them
}