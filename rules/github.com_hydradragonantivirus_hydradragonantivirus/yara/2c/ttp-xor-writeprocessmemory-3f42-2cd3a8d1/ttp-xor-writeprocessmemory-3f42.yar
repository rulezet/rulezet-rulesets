rule TTP_XOR_WriteProcessMemory_3f42 {
  strings:
    $key_3f42 = { 68 30 [2] 5a 12 [2] 5c 27 [2] 72 27 [2] 4d 3b }

  condition:
    any of them
}