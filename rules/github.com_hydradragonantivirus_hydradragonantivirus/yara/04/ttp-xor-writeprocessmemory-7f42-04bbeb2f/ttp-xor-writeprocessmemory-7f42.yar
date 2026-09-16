rule TTP_XOR_WriteProcessMemory_7f42 {
  strings:
    $key_7f42 = { 28 30 [2] 1a 12 [2] 1c 27 [2] 32 27 [2] 0d 3b }

  condition:
    any of them
}