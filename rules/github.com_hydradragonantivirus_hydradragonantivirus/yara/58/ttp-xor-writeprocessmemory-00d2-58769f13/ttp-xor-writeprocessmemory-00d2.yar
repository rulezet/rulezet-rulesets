rule TTP_XOR_WriteProcessMemory_00d2 {
  strings:
    $key_00d2 = { 57 a0 [2] 65 82 [2] 63 b7 [2] 4d b7 [2] 72 ab }

  condition:
    any of them
}