rule TTP_XOR_WriteProcessMemory_547f {
  strings:
    $key_547f = { 03 0d [2] 31 2f [2] 37 1a [2] 19 1a [2] 26 06 }

  condition:
    any of them
}