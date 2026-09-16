rule TTP_XOR_WriteProcessMemory_5308 {
  strings:
    $key_5308 = { 04 7a [2] 36 58 [2] 30 6d [2] 1e 6d [2] 21 71 }

  condition:
    any of them
}