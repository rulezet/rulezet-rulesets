rule TTP_XOR_WriteProcessMemory_1da3 {
  strings:
    $key_1da3 = { 4a d1 [2] 78 f3 [2] 7e c6 [2] 50 c6 [2] 6f da }

  condition:
    any of them
}