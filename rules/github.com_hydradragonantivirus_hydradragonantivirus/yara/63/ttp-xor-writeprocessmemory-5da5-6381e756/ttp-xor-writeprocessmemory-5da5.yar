rule TTP_XOR_WriteProcessMemory_5da5 {
  strings:
    $key_5da5 = { 0a d7 [2] 38 f5 [2] 3e c0 [2] 10 c0 [2] 2f dc }

  condition:
    any of them
}