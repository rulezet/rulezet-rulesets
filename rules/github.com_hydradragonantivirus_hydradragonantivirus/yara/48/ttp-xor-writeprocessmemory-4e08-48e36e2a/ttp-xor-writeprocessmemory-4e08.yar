rule TTP_XOR_WriteProcessMemory_4e08 {
  strings:
    $key_4e08 = { 19 7a [2] 2b 58 [2] 2d 6d [2] 03 6d [2] 3c 71 }

  condition:
    any of them
}