rule TTP_XOR_WriteProcessMemory_1f78 {
  strings:
    $key_1f78 = { 48 0a [2] 7a 28 [2] 7c 1d [2] 52 1d [2] 6d 01 }

  condition:
    any of them
}