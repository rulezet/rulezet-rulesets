rule TTP_XOR_WriteProcessMemory_4808 {
  strings:
    $key_4808 = { 1f 7a [2] 2d 58 [2] 2b 6d [2] 05 6d [2] 3a 71 }

  condition:
    any of them
}