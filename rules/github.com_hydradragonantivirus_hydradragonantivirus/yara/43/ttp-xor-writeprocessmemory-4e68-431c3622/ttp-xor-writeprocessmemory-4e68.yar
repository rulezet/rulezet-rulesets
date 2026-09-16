rule TTP_XOR_WriteProcessMemory_4e68 {
  strings:
    $key_4e68 = { 19 1a [2] 2b 38 [2] 2d 0d [2] 03 0d [2] 3c 11 }

  condition:
    any of them
}