rule TTP_XOR_WriteProcessMemory_3da5 {
  strings:
    $key_3da5 = { 6a d7 [2] 58 f5 [2] 5e c0 [2] 70 c0 [2] 4f dc }

  condition:
    any of them
}