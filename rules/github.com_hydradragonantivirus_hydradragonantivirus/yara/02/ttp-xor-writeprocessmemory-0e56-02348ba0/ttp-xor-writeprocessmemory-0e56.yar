rule TTP_XOR_WriteProcessMemory_0e56 {
  strings:
    $key_0e56 = { 59 24 [2] 6b 06 [2] 6d 33 [2] 43 33 [2] 7c 2f }

  condition:
    any of them
}