rule TTP_XOR_WriteProcessMemory_0032 {
  strings:
    $key_0032 = { 57 40 [2] 65 62 [2] 63 57 [2] 4d 57 [2] 72 4b }

  condition:
    any of them
}