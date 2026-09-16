rule TTP_XOR_WriteProcessMemory_5178 {
  strings:
    $key_5178 = { 06 0a [2] 34 28 [2] 32 1d [2] 1c 1d [2] 23 01 }

  condition:
    any of them
}