rule TTP_XOR_WriteProcessMemory_4a1f {
  strings:
    $key_4a1f = { 1d 6d [2] 2f 4f [2] 29 7a [2] 07 7a [2] 38 66 }

  condition:
    any of them
}