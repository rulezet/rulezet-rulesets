rule TTP_XOR_WriteProcessMemory_7f56 {
  strings:
    $key_7f56 = { 28 24 [2] 1a 06 [2] 1c 33 [2] 32 33 [2] 0d 2f }

  condition:
    any of them
}