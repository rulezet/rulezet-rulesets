rule TTP_XOR_WriteProcessMemory_7208 {
  strings:
    $key_7208 = { 25 7a [2] 17 58 [2] 11 6d [2] 3f 6d [2] 00 71 }

  condition:
    any of them
}