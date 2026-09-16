rule TTP_XOR_WriteProcessMemory_7e68 {
  strings:
    $key_7e68 = { 29 1a [2] 1b 38 [2] 1d 0d [2] 33 0d [2] 0c 11 }

  condition:
    any of them
}