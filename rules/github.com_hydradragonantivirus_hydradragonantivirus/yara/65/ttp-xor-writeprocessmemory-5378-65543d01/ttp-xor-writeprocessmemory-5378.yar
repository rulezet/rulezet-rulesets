rule TTP_XOR_WriteProcessMemory_5378 {
  strings:
    $key_5378 = { 04 0a [2] 36 28 [2] 30 1d [2] 1e 1d [2] 21 01 }

  condition:
    any of them
}