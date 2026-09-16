rule TTP_XOR_WriteProcessMemory_6d78 {
  strings:
    $key_6d78 = { 3a 0a [2] 08 28 [2] 0e 1d [2] 20 1d [2] 1f 01 }

  condition:
    any of them
}