rule TTP_XOR_WriteProcessMemory_5f1f {
  strings:
    $key_5f1f = { 08 6d [2] 3a 4f [2] 3c 7a [2] 12 7a [2] 2d 66 }

  condition:
    any of them
}