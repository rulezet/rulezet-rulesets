rule TTP_XOR_WriteProcessMemory_2d78 {
  strings:
    $key_2d78 = { 7a 0a [2] 48 28 [2] 4e 1d [2] 60 1d [2] 5f 01 }

  condition:
    any of them
}