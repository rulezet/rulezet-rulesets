rule TTP_XOR_WriteProcessMemory_7e6f {
  strings:
    $key_7e6f = { 29 1d [2] 1b 3f [2] 1d 0a [2] 33 0a [2] 0c 16 }

  condition:
    any of them
}