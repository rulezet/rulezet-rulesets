rule TTP_XOR_WriteProcessMemory_3552 {
  strings:
    $key_3552 = { 62 20 [2] 50 02 [2] 56 37 [2] 78 37 [2] 47 2b }

  condition:
    any of them
}