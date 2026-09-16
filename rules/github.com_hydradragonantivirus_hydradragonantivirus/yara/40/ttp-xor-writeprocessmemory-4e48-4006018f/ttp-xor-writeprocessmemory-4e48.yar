rule TTP_XOR_WriteProcessMemory_4e48 {
  strings:
    $key_4e48 = { 19 3a [2] 2b 18 [2] 2d 2d [2] 03 2d [2] 3c 31 }

  condition:
    any of them
}