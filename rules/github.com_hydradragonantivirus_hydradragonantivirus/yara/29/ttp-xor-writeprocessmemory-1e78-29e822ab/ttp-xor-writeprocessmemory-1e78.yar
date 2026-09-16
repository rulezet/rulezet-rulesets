rule TTP_XOR_WriteProcessMemory_1e78 {
  strings:
    $key_1e78 = { 49 0a [2] 7b 28 [2] 7d 1d [2] 53 1d [2] 6c 01 }

  condition:
    any of them
}