rule TTP_XOR_WriteProcessMemory_5ff8 {
  strings:
    $key_5ff8 = { 08 8a [2] 3a a8 [2] 3c 9d [2] 12 9d [2] 2d 81 }

  condition:
    any of them
}