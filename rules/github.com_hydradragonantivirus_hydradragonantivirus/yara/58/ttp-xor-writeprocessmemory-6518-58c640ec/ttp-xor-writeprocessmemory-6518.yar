rule TTP_XOR_WriteProcessMemory_6518 {
  strings:
    $key_6518 = { 32 6a [2] 00 48 [2] 06 7d [2] 28 7d [2] 17 61 }

  condition:
    any of them
}