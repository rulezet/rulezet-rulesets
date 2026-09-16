rule TTP_XOR_WriteProcessMemory_1f7f {
  strings:
    $key_1f7f = { 48 0d [2] 7a 2f [2] 7c 1a [2] 52 1a [2] 6d 06 }

  condition:
    any of them
}