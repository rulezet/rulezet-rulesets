rule TTP_XOR_WriteProcessMemory_00d1 {
  strings:
    $key_00d1 = { 57 a3 [2] 65 81 [2] 63 b4 [2] 4d b4 [2] 72 a8 }

  condition:
    any of them
}