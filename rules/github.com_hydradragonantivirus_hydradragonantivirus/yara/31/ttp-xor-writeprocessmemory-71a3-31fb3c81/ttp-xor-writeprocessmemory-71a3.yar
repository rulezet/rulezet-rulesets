rule TTP_XOR_WriteProcessMemory_71a3 {
  strings:
    $key_71a3 = { 26 d1 [2] 14 f3 [2] 12 c6 [2] 3c c6 [2] 03 da }

  condition:
    any of them
}