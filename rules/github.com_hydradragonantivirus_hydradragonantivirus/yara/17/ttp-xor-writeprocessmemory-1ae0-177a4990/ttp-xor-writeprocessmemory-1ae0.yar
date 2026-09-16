rule TTP_XOR_WriteProcessMemory_1ae0 {
  strings:
    $key_1ae0 = { 4d 92 [2] 7f b0 [2] 79 85 [2] 57 85 [2] 68 99 }

  condition:
    any of them
}