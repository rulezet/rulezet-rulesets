rule TTP_XOR_WriteProcessMemory_7e4a {
  strings:
    $key_7e4a = { 29 38 [2] 1b 1a [2] 1d 2f [2] 33 2f [2] 0c 33 }

  condition:
    any of them
}