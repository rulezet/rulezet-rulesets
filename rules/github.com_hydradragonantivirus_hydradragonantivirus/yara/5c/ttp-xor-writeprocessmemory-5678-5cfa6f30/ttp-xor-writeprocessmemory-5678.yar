rule TTP_XOR_WriteProcessMemory_5678 {
  strings:
    $key_5678 = { 01 0a [2] 33 28 [2] 35 1d [2] 1b 1d [2] 24 01 }

  condition:
    any of them
}