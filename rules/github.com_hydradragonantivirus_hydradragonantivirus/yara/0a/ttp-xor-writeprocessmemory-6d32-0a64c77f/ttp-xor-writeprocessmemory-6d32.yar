rule TTP_XOR_WriteProcessMemory_6d32 {
  strings:
    $key_6d32 = { 3a 40 [2] 08 62 [2] 0e 57 [2] 20 57 [2] 1f 4b }

  condition:
    any of them
}