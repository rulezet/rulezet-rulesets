rule TTP_XOR_WriteProcessMemory_7108 {
  strings:
    $key_7108 = { 26 7a [2] 14 58 [2] 12 6d [2] 3c 6d [2] 03 71 }

  condition:
    any of them
}