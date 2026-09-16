rule TTP_XOR_WriteProcessMemory_7da5 {
  strings:
    $key_7da5 = { 2a d7 [2] 18 f5 [2] 1e c0 [2] 30 c0 [2] 0f dc }

  condition:
    any of them
}