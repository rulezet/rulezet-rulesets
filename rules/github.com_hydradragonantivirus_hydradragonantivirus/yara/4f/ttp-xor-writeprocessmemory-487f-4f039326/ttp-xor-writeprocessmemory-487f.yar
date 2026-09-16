rule TTP_XOR_WriteProcessMemory_487f {
  strings:
    $key_487f = { 1f 0d [2] 2d 2f [2] 2b 1a [2] 05 1a [2] 3a 06 }

  condition:
    any of them
}