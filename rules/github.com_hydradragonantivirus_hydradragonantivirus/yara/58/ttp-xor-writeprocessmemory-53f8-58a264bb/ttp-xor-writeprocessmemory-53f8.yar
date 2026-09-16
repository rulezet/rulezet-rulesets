rule TTP_XOR_WriteProcessMemory_53f8 {
  strings:
    $key_53f8 = { 04 8a [2] 36 a8 [2] 30 9d [2] 1e 9d [2] 21 81 }

  condition:
    any of them
}