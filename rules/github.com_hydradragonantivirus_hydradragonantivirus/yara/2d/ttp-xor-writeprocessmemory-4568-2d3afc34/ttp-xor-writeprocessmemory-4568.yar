rule TTP_XOR_WriteProcessMemory_4568 {
  strings:
    $key_4568 = { 12 1a [2] 20 38 [2] 26 0d [2] 08 0d [2] 37 11 }

  condition:
    any of them
}