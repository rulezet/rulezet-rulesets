rule TTP_XOR_WriteProcessMemory_5a7f {
  strings:
    $key_5a7f = { 0d 0d [2] 3f 2f [2] 39 1a [2] 17 1a [2] 28 06 }

  condition:
    any of them
}