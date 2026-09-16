rule TTP_XOR_WriteProcessMemory_00d9 {
  strings:
    $key_00d9 = { 57 ab [2] 65 89 [2] 63 bc [2] 4d bc [2] 72 a0 }

  condition:
    any of them
}