rule TTP_XOR_WriteProcessMemory_00a6 {
  strings:
    $key_00a6 = { 57 d4 [2] 65 f6 [2] 63 c3 [2] 4d c3 [2] 72 df }

  condition:
    any of them
}