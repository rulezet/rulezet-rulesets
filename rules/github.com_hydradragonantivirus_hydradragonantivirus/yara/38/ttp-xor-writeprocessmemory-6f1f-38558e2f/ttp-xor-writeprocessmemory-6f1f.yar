rule TTP_XOR_WriteProcessMemory_6f1f {
  strings:
    $key_6f1f = { 38 6d [2] 0a 4f [2] 0c 7a [2] 22 7a [2] 1d 66 }

  condition:
    any of them
}