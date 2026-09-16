rule TTP_XOR_WriteProcessMemory_31a3 {
  strings:
    $key_31a3 = { 66 d1 [2] 54 f3 [2] 52 c6 [2] 7c c6 [2] 43 da }

  condition:
    any of them
}