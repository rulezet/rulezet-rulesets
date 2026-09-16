rule TTP_XOR_WriteProcessMemory_5f18 {
  strings:
    $key_5f18 = { 08 6a [2] 3a 48 [2] 3c 7d [2] 12 7d [2] 2d 61 }

  condition:
    any of them
}