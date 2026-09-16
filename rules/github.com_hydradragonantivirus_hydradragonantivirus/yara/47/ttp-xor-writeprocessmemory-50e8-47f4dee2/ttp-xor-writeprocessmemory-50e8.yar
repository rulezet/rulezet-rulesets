rule TTP_XOR_WriteProcessMemory_50e8 {
  strings:
    $key_50e8 = { 07 9a [2] 35 b8 [2] 33 8d [2] 1d 8d [2] 22 91 }

  condition:
    any of them
}