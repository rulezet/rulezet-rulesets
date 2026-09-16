rule TTP_XOR_WriteProcessMemory_4a78 {
  strings:
    $key_4a78 = { 1d 0a [2] 2f 28 [2] 29 1d [2] 07 1d [2] 38 01 }

  condition:
    any of them
}