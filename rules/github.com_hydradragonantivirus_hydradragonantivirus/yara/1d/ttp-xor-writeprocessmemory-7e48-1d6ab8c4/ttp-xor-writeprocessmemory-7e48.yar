rule TTP_XOR_WriteProcessMemory_7e48 {
  strings:
    $key_7e48 = { 29 3a [2] 1b 18 [2] 1d 2d [2] 33 2d [2] 0c 31 }

  condition:
    any of them
}