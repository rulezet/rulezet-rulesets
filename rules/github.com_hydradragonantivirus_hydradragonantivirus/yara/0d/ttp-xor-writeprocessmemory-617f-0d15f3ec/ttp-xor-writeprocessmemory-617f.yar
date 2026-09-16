rule TTP_XOR_WriteProcessMemory_617f {
  strings:
    $key_617f = { 36 0d [2] 04 2f [2] 02 1a [2] 2c 1a [2] 13 06 }

  condition:
    any of them
}