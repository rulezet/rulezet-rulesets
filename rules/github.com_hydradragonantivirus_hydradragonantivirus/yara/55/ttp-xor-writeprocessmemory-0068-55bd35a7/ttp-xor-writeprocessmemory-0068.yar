rule TTP_XOR_WriteProcessMemory_0068 {
  strings:
    $key_0068 = { 57 1a [2] 65 38 [2] 63 0d [2] 4d 0d [2] 72 11 }

  condition:
    any of them
}