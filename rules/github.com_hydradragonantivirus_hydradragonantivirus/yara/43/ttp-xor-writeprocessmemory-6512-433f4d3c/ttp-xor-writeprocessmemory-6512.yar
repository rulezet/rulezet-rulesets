rule TTP_XOR_WriteProcessMemory_6512 {
  strings:
    $key_6512 = { 32 60 [2] 00 42 [2] 06 77 [2] 28 77 [2] 17 6b }

  condition:
    any of them
}