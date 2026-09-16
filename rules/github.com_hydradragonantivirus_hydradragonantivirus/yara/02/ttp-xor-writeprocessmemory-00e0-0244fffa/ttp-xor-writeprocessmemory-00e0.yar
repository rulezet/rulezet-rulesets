rule TTP_XOR_WriteProcessMemory_00e0 {
  strings:
    $key_00e0 = { 57 92 [2] 65 b0 [2] 63 85 [2] 4d 85 [2] 72 99 }

  condition:
    any of them
}