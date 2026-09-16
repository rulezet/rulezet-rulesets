rule TTP_XOR_WriteProcessMemory_7456 {
  strings:
    $key_7456 = { 23 24 [2] 11 06 [2] 17 33 [2] 39 33 [2] 06 2f }

  condition:
    any of them
}