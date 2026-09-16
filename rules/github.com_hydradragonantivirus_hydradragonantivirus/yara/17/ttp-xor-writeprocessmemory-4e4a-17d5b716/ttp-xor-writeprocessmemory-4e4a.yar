rule TTP_XOR_WriteProcessMemory_4e4a {
  strings:
    $key_4e4a = { 19 38 [2] 2b 1a [2] 2d 2f [2] 03 2f [2] 3c 33 }

  condition:
    any of them
}