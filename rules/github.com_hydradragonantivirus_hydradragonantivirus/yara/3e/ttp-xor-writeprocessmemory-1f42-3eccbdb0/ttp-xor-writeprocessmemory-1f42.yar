rule TTP_XOR_WriteProcessMemory_1f42 {
  strings:
    $key_1f42 = { 48 30 [2] 7a 12 [2] 7c 27 [2] 52 27 [2] 6d 3b }

  condition:
    any of them
}