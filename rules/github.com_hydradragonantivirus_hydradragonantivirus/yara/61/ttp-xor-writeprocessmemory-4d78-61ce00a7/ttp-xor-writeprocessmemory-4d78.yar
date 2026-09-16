rule TTP_XOR_WriteProcessMemory_4d78 {
  strings:
    $key_4d78 = { 1a 0a [2] 28 28 [2] 2e 1d [2] 00 1d [2] 3f 01 }

  condition:
    any of them
}