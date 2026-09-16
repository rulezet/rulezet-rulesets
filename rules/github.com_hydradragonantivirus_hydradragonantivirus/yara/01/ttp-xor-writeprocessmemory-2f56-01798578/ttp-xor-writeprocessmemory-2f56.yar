rule TTP_XOR_WriteProcessMemory_2f56 {
  strings:
    $key_2f56 = { 78 24 [2] 4a 06 [2] 4c 33 [2] 62 33 [2] 5d 2f }

  condition:
    any of them
}