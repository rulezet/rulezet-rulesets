rule TTP_XOR_WriteProcessMemory_2378 {
  strings:
    $key_2378 = { 74 0a [2] 46 28 [2] 40 1d [2] 6e 1d [2] 51 01 }

  condition:
    any of them
}