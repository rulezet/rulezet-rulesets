rule TTP_XOR_WriteProcessMemory_545f {
  strings:
    $key_545f = { 03 2d [2] 31 0f [2] 37 3a [2] 19 3a [2] 26 26 }

  condition:
    any of them
}