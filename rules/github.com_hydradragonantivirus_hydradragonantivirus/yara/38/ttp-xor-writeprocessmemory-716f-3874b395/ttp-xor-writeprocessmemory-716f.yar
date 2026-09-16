rule TTP_XOR_WriteProcessMemory_716f {
  strings:
    $key_716f = { 26 1d [2] 14 3f [2] 12 0a [2] 3c 0a [2] 03 16 }

  condition:
    any of them
}