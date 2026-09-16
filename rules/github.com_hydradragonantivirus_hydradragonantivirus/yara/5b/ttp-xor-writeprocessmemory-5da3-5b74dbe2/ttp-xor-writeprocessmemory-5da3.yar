rule TTP_XOR_WriteProcessMemory_5da3 {
  strings:
    $key_5da3 = { 0a d1 [2] 38 f3 [2] 3e c6 [2] 10 c6 [2] 2f da }

  condition:
    any of them
}