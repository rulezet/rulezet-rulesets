rule TTP_XOR_WriteProcessMemory_1878 {
  strings:
    $key_1878 = { 4f 0a [2] 7d 28 [2] 7b 1d [2] 55 1d [2] 6a 01 }

  condition:
    any of them
}