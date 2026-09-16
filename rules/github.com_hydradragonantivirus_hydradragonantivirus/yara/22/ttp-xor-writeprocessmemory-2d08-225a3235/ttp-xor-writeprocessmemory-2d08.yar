rule TTP_XOR_WriteProcessMemory_2d08 {
  strings:
    $key_2d08 = { 7a 7a [2] 48 58 [2] 4e 6d [2] 60 6d [2] 5f 71 }

  condition:
    any of them
}