rule TTP_XOR_WriteProcessMemory_3332 {
  strings:
    $key_3332 = { 64 40 [2] 56 62 [2] 50 57 [2] 7e 57 [2] 41 4b }

  condition:
    any of them
}