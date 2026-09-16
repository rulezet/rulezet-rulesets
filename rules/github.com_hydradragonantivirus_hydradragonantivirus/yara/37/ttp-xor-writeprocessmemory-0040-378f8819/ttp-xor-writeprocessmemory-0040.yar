rule TTP_XOR_WriteProcessMemory_0040 {
  strings:
    $key_0040 = { 57 32 [2] 65 10 [2] 63 25 [2] 4d 25 [2] 72 39 }

  condition:
    any of them
}