rule TTP_XOR_WriteProcessMemory_1f6f {
  strings:
    $key_1f6f = { 48 1d [2] 7a 3f [2] 7c 0a [2] 52 0a [2] 6d 16 }

  condition:
    any of them
}