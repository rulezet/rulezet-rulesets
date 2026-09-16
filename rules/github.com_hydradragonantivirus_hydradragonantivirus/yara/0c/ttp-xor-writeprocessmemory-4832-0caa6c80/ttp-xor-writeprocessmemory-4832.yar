rule TTP_XOR_WriteProcessMemory_4832 {
  strings:
    $key_4832 = { 1f 40 [2] 2d 62 [2] 2b 57 [2] 05 57 [2] 3a 4b }

  condition:
    any of them
}