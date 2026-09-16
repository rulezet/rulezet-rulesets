rule TTP_XOR_WriteProcessMemory_53e8 {
  strings:
    $key_53e8 = { 04 9a [2] 36 b8 [2] 30 8d [2] 1e 8d [2] 21 91 }

  condition:
    any of them
}