rule TTP_XOR_WriteProcessMemory_63e8 {
  strings:
    $key_63e8 = { 34 9a [2] 06 b8 [2] 00 8d [2] 2e 8d [2] 11 91 }

  condition:
    any of them
}