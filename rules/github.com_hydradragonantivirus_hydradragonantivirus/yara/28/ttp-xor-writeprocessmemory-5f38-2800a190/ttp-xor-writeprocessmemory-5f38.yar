rule TTP_XOR_WriteProcessMemory_5f38 {
  strings:
    $key_5f38 = { 08 4a [2] 3a 68 [2] 3c 5d [2] 12 5d [2] 2d 41 }

  condition:
    any of them
}