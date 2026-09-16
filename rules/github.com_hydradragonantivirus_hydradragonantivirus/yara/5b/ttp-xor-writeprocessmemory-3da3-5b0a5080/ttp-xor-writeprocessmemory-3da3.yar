rule TTP_XOR_WriteProcessMemory_3da3 {
  strings:
    $key_3da3 = { 6a d1 [2] 58 f3 [2] 5e c6 [2] 70 c6 [2] 4f da }

  condition:
    any of them
}