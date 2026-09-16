rule TTP_XOR_WriteProcessMemory_781f {
  strings:
    $key_781f = { 2f 6d [2] 1d 4f [2] 1b 7a [2] 35 7a [2] 0a 66 }

  condition:
    any of them
}