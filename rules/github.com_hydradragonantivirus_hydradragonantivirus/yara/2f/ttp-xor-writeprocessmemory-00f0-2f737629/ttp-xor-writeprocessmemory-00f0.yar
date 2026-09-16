rule TTP_XOR_WriteProcessMemory_00f0 {
  strings:
    $key_00f0 = { 57 82 [2] 65 a0 [2] 63 95 [2] 4d 95 [2] 72 89 }

  condition:
    any of them
}