rule TTP_XOR_WriteProcessMemory_6f56 {
  strings:
    $key_6f56 = { 38 24 [2] 0a 06 [2] 0c 33 [2] 22 33 [2] 1d 2f }

  condition:
    any of them
}