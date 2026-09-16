rule TTP_XOR_WriteProcessMemory_1da5 {
  strings:
    $key_1da5 = { 4a d7 [2] 78 f5 [2] 7e c0 [2] 50 c0 [2] 6f dc }

  condition:
    any of them
}