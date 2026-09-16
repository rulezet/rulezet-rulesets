rule TTP_XOR_WriteProcessMemory_7748 {
  strings:
    $key_7748 = { 20 3a [2] 12 18 [2] 14 2d [2] 3a 2d [2] 05 31 }

  condition:
    any of them
}