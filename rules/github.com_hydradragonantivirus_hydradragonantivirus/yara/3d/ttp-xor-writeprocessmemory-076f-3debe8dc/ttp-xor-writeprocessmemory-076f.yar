rule TTP_XOR_WriteProcessMemory_076f {
  strings:
    $key_076f = { 50 1d [2] 62 3f [2] 64 0a [2] 4a 0a [2] 75 16 }

  condition:
    any of them
}