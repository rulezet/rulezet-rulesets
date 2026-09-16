rule TTP_XOR_WriteProcessMemory_65e8 {
  strings:
    $key_65e8 = { 32 9a [2] 00 b8 [2] 06 8d [2] 28 8d [2] 17 91 }

  condition:
    any of them
}