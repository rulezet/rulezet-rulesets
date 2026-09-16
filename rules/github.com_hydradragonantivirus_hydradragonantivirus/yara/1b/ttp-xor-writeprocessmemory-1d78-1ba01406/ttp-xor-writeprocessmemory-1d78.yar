rule TTP_XOR_WriteProcessMemory_1d78 {
  strings:
    $key_1d78 = { 4a 0a [2] 78 28 [2] 7e 1d [2] 50 1d [2] 6f 01 }

  condition:
    any of them
}