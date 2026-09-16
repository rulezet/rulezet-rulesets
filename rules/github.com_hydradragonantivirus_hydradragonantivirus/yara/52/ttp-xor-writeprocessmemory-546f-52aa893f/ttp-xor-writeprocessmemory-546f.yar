rule TTP_XOR_WriteProcessMemory_546f {
  strings:
    $key_546f = { 03 1d [2] 31 3f [2] 37 0a [2] 19 0a [2] 26 16 }

  condition:
    any of them
}