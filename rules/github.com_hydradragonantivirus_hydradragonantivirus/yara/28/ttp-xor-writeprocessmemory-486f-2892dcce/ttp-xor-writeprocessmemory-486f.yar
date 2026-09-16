rule TTP_XOR_WriteProcessMemory_486f {
  strings:
    $key_486f = { 1f 1d [2] 2d 3f [2] 2b 0a [2] 05 0a [2] 3a 16 }

  condition:
    any of them
}