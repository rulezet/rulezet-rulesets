rule TTP_XOR_WriteProcessMemory_4077 {
  strings:
    $key_4077 = { 17 05 [2] 25 27 [2] 23 12 [2] 0d 12 [2] 32 0e }

  condition:
    any of them
}