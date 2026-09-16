rule TTP_XOR_WriteProcessMemory_57e8 {
  strings:
    $key_57e8 = { 00 9a [2] 32 b8 [2] 34 8d [2] 1a 8d [2] 25 91 }

  condition:
    any of them
}