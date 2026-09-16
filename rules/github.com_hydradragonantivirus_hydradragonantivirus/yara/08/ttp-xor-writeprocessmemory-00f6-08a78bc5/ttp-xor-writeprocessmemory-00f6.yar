rule TTP_XOR_WriteProcessMemory_00f6 {
  strings:
    $key_00f6 = { 57 84 [2] 65 a6 [2] 63 93 [2] 4d 93 [2] 72 8f }

  condition:
    any of them
}