rule TTP_XOR_WriteProcessMemory_00a5 {
  strings:
    $key_00a5 = { 57 d7 [2] 65 f5 [2] 63 c0 [2] 4d c0 [2] 72 dc }

  condition:
    any of them
}