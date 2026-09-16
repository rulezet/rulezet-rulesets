rule TTP_XOR_WriteProcessMemory_2f62 {
  strings:
    $key_2f62 = { 78 10 [2] 4a 32 [2] 4c 07 [2] 62 07 [2] 5d 1b }

  condition:
    any of them
}