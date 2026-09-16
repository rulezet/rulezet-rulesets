rule TTP_XOR_WriteProcessMemory_6762 {
  strings:
    $key_6762 = { 30 10 [2] 02 32 [2] 04 07 [2] 2a 07 [2] 15 1b }

  condition:
    any of them
}