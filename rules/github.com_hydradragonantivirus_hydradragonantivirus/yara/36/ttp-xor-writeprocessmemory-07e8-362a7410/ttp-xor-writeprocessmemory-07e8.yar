rule TTP_XOR_WriteProcessMemory_07e8 {
  strings:
    $key_07e8 = { 50 9a [2] 62 b8 [2] 64 8d [2] 4a 8d [2] 75 91 }

  condition:
    any of them
}