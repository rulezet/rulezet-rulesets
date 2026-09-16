rule TTP_XOR_WriteProcessMemory_7568 {
  strings:
    $key_7568 = { 22 1a [2] 10 38 [2] 16 0d [2] 38 0d [2] 07 11 }

  condition:
    any of them
}