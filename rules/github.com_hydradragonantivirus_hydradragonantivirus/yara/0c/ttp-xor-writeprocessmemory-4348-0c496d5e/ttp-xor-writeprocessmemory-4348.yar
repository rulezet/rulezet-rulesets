rule TTP_XOR_WriteProcessMemory_4348 {
  strings:
    $key_4348 = { 14 3a [2] 26 18 [2] 20 2d [2] 0e 2d [2] 31 31 }

  condition:
    any of them
}