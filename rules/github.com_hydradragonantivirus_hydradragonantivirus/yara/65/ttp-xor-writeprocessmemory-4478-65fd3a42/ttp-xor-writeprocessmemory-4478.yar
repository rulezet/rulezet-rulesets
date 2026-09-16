rule TTP_XOR_WriteProcessMemory_4478 {
  strings:
    $key_4478 = { 13 0a [2] 21 28 [2] 27 1d [2] 09 1d [2] 36 01 }

  condition:
    any of them
}