rule TTP_XOR_WriteProcessMemory_7848 {
  strings:
    $key_7848 = { 2f 3a [2] 1d 18 [2] 1b 2d [2] 35 2d [2] 0a 31 }

  condition:
    any of them
}