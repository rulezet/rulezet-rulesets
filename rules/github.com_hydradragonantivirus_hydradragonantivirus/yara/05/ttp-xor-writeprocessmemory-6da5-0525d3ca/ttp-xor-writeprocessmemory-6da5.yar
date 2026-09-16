rule TTP_XOR_WriteProcessMemory_6da5 {
  strings:
    $key_6da5 = { 3a d7 [2] 08 f5 [2] 0e c0 [2] 20 c0 [2] 1f dc }

  condition:
    any of them
}