rule TTP_XOR_WriteProcessMemory_6f62 {
  strings:
    $key_6f62 = { 38 10 [2] 0a 32 [2] 0c 07 [2] 22 07 [2] 1d 1b }

  condition:
    any of them
}